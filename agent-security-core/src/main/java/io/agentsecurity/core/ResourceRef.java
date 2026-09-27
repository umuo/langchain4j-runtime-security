package io.agentsecurity.core;

/** 请求访问的资源引用，不证明资源归属；标识需要由可信授权服务与调用者身份联合校验。 */
public record ResourceRef(String type, String id) {

    public ResourceRef {
        if (type == null || !type.matches("[a-z:-]{1,40}") || id == null || id.length() > 1024) {
            throw new IllegalArgumentException("Invalid resource reference");
        }
    }

    @Override
    public String toString() {
        return "ResourceRef[type=" + type + "]";
    }
}
