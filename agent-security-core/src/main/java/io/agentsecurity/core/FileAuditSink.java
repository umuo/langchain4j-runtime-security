package io.agentsecurity.core;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.function.BiConsumer;
import static java.nio.file.StandardOpenOption.*;

/** Bounded JSONL decision journal. No payloads, tool names, identities or plugin exception text. */
public final class FileAuditSink implements BiConsumer<SecurityEvent, Decision>, AutoCloseable {
    private final Path path;
    private final long maxBytes;
    private final int backups;
    private final boolean force;
    private final String policyVersion;
    private final FileChannel lockChannel;
    private final FileLock lock;
    private FileChannel output;
    private boolean closed;
    private boolean failed;

    public FileAuditSink(Path path, long maxBytes, int backups, boolean force, String policyVersion) throws IOException {
        if (maxBytes < 1024 || maxBytes > (1L << 40)) throw new IllegalArgumentException("Invalid audit.max.bytes");
        if (backups < 1 || backups > 100) throw new IllegalArgumentException("Invalid audit.backups");
        if (policyVersion == null || !policyVersion.matches("[a-zA-Z0-9_.-]{1,80}")) throw new IllegalArgumentException("Invalid policy.version");
        this.path = path.toAbsolutePath().normalize(); this.maxBytes = maxBytes; this.backups = backups;
        this.force = force; this.policyVersion = policyVersion;
        Files.createDirectories(this.path.getParent());
        Path lockPath = this.path.resolveSibling(this.path.getFileName() + ".lock");
        createPrivateFile(lockPath);
        lockChannel = FileChannel.open(lockPath, WRITE, LinkOption.NOFOLLOW_LINKS);
        FileLock acquired = null;
        try {
            acquired = lockChannel.tryLock();
            if (acquired == null) throw new IOException("Audit journal is already in use");
            lock = acquired;
            output = openOutput();
        } catch (IOException | RuntimeException error) {
            if (acquired != null) acquired.close();
            lockChannel.close();
            throw error;
        }
    }

    @Override public synchronized void accept(SecurityEvent event, Decision decision) {
        if (closed || failed) throw new IllegalStateException("Audit journal unavailable");
        String runId = event.context() == null ? "null" : "\"" + event.context().runId() + "\"";
        String line = "{\"schemaVersion\":2,\"runId\":" + runId + ",\"time\":\"" + Instant.now() + "\",\"eventId\":\"" + event.id()
                + "\",\"phase\":\"" + event.phase() + "\",\"decision\":\"" + (decision.allowed() ? "ALLOW" : "DENY")
                + "\",\"ruleId\":\"" + decision.ruleId() + "\",\"policyVersion\":\"" + policyVersion + "\"}\n";
        byte[] bytes = line.getBytes(StandardCharsets.UTF_8);
        try {
            if (output.size() + bytes.length > maxBytes) rotate();
            ByteBuffer buffer = ByteBuffer.wrap(bytes);
            while (buffer.hasRemaining()) output.write(buffer);
            if (force) output.force(true);
        } catch (IOException e) {
            failed = true; // A partial record or failed rotation must never be followed by more accepted records.
            throw new UncheckedIOException("audit-write-failed", e);
        }
    }

    private void rotate() throws IOException {
        for (int index = 1; index <= backups; index++) validateRegular(backup(index));
        if (force) output.force(true);
        output.close();
        for (int index = backups; index >= 2; index--)
            if (Files.exists(backup(index - 1), LinkOption.NOFOLLOW_LINKS))
                Files.move(backup(index - 1), backup(index), StandardCopyOption.REPLACE_EXISTING);
        Files.move(path, backup(1), StandardCopyOption.REPLACE_EXISTING);
        output = openOutput();
    }

    private Path backup(int index) { return path.resolveSibling(path.getFileName() + "." + index); }

    private FileChannel openOutput() throws IOException {
        createPrivateFile(path);
        return FileChannel.open(path, WRITE, APPEND, LinkOption.NOFOLLOW_LINKS);
    }

    private static void validateRegular(Path file) throws IOException {
        if (Files.exists(file, LinkOption.NOFOLLOW_LINKS) && !Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS))
            throw new IOException("Audit paths must be regular files");
    }

    private static void createPrivateFile(Path file) throws IOException {
        validateRegular(file);
        if (Files.exists(file, LinkOption.NOFOLLOW_LINKS)) return;
        try {
            Files.createFile(file, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
        } catch (UnsupportedOperationException e) {
            Files.createFile(file); // Windows access follows the parent directory ACL.
        } catch (FileAlreadyExistsException e) { validateRegular(file); }
    }

    @Override public synchronized void close() throws IOException {
        if (closed) return;
        closed = true;
        try { if (output != null) output.close(); }
        finally { try { lock.close(); } finally { lockChannel.close(); } }
    }
}
