package io.github.cuukenn.encryptor.protocol;

import io.github.cuukenn.encryptor.audit.EncryptorListener;
import io.github.cuukenn.encryptor.jose.NonceChecker;

import java.util.Collection;
import java.util.LinkedHashSet;

/**
 * servlet 与 reactive 两侧共用的协议栈组装入口。
 *
 * <p>两侧的 Spring 配置前缀不同，但落到 {@link DefaultProtocol.Builder} 的规则必须一致：
 * 密钥、active-kid、算法白名单、TTL/nonce 保留期、容量、共享 nonce 存储、监听器与运行期旁路。
 * 把这些规则收在这里，避免只改一侧导致“servlet 正常、网关失败”。</p>
 *
 * @author changgg
 */
public final class ProtocolAssembler {

    private ProtocolAssembler() {
    }

    /**
     * 按配置组装协议栈；非法配置由 {@link DefaultProtocol.Builder#build()} 启动期 fail-fast。
     *
     * @param keys                密钥材料（至少一把）
     * @param activeKid           当前签发/下发使用的 kid；空则用第一把
     * @param allowedAlgs         算法白名单；空则按密钥类型推导
     * @param allowedEncs         内容加密白名单；空则按密钥类型推导
     * @param ttlMillis           请求时间窗（毫秒）；null 用默认值
     * @param nonceRetentionMillis nonce 保留期（毫秒）；null/非正数用 TTL
     * @param nonceCapacity       内置内存 nonce 存储容量
     * @param nonceChecker        自定义 nonce 存储；null 用内置内存实现
     * @param listener            监听器（通常是多个监听器的组合）；null/空组合用 NONE
     * @param bypassRequest       启动时是否旁路请求方向
     * @param bypassResponse      启动时是否旁路响应方向
     * @return 已装配好的协议栈
     */
    public static DefaultProtocol assemble(Collection<DefaultProtocol.KeyMaterial> keys,
                                           String activeKid,
                                           Collection<String> allowedAlgs,
                                           Collection<String> allowedEncs,
                                           Long ttlMillis,
                                           Long nonceRetentionMillis,
                                           int nonceCapacity,
                                           NonceChecker nonceChecker,
                                           EncryptorListener listener,
                                           boolean bypassRequest,
                                           boolean bypassResponse) {
        DefaultProtocol.Builder builder = DefaultProtocol.builder().keys(keys);
        if (activeKid != null && !activeKid.isEmpty()) {
            builder.activeKid(activeKid);
        }
        if (allowedAlgs != null && !allowedAlgs.isEmpty()) {
            builder.allowedAlgs(new LinkedHashSet<>(allowedAlgs));
        }
        if (allowedEncs != null && !allowedEncs.isEmpty()) {
            builder.allowedEncs(new LinkedHashSet<>(allowedEncs));
        }
        if (ttlMillis != null) {
            builder.ttlMillis(ttlMillis);
        }
        if (nonceRetentionMillis != null) {
            builder.nonceRetentionMillis(nonceRetentionMillis);
        }
        builder.nonceCapacity(nonceCapacity);
        if (nonceChecker != null) {
            builder.nonceChecker(nonceChecker);
        }
        if (listener != null && listener != EncryptorListener.NONE) {
            builder.listener(listener);
        }
        DefaultProtocol protocol = builder.build();
        protocol.runtime().setBypass(bypassRequest, bypassResponse);
        return protocol;
    }
}
