package io.github.cuukenn.encryptor.reactive.configuration;

import io.github.cuukenn.encryptor.audit.EncryptorListener;
import io.github.cuukenn.encryptor.jose.NonceChecker;
import io.github.cuukenn.encryptor.reactive.config.EncryptorConfig;
import io.github.cuukenn.encryptor.reactive.config.KeyMaterialConfig;
import io.github.cuukenn.encryptor.protocol.DefaultProtocol;
import io.github.cuukenn.encryptor.runtime.EncryptorRuntime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.LinkedHashSet;

/**
 * v2 协议的通用自动装配（reactive 侧）：与 servlet 侧装配<b>同一份</b> core {@link DefaultProtocol}，
 * 算法栈不在此出现；所有非法配置在启动期 fail-fast。
 *
 * @author changgg
 */
@EnableConfigurationProperties(EncryptorConfig.class)
@ConditionalOnProperty(prefix = EncryptorConfig.PREFIX, name = "enable", havingValue = "true", matchIfMissing = true)
@Configuration(proxyBeanMethods = false)
public class EncryptorReactiveAutoConfiguration {
    private static final Logger logger = LoggerFactory.getLogger(EncryptorReactiveAutoConfiguration.class);

    /**
     * v2 协议栈（密钥库 + JWE 编解码 + 防重放 + 运行期开关）。
     */
    @Bean
    @ConditionalOnMissingBean
    public DefaultProtocol defaultProtocol(EncryptorConfig config, ObjectProvider<EncryptorListener> listener,
                                           ObjectProvider<NonceChecker> nonceChecker) {
        DefaultProtocol.Builder builder = DefaultProtocol.builder();
        for (KeyMaterialConfig key : config.getKeys()) {
            builder.key(new DefaultProtocol.KeyMaterial(key.getKid(), key.getType(), key.getPrivateKey(), key.getPublicKey()));
        }
        if (config.getActiveKid() != null && !config.getActiveKid().isEmpty()) {
            builder.activeKid(config.getActiveKid());
        }
        if (!config.getAllowedAlgs().isEmpty()) {
            builder.allowedAlgs(new LinkedHashSet<>(config.getAllowedAlgs()));
        }
        if (!config.getAllowedEncs().isEmpty()) {
            builder.allowedEncs(new LinkedHashSet<>(config.getAllowedEncs()));
        }
        if (config.getTtl() != null) {
            builder.ttlMillis(config.getTtl().toMillis());
        }
        if (config.getNonceRetention() != null) {
            builder.nonceRetentionMillis(config.getNonceRetention().toMillis());
        }
        builder.nonceCapacity(config.getNonceCapacity());
        // 多实例网关：注册自己的 NonceChecker bean（如 Redis 共享存储）即可替换内存实现，
        // 无需覆盖整个 DefaultProtocol（否则连密钥库一起换掉）
        NonceChecker sharedNonceChecker = nonceChecker.getIfAvailable();
        if (sharedNonceChecker != null) {
            builder.nonceChecker(sharedNonceChecker);
        }
        EncryptorListener contextListener = listener.getIfAvailable();
        if (contextListener != null) {
            builder.listener(contextListener);
        }
        DefaultProtocol protocol = builder.build();
        protocol.runtime().setBypass(config.getBypass().isRequest(), config.getBypass().isResponse());
        warnRiskyConfig(config);
        logSummary(config, protocol);
        return protocol;
    }

    /**
     * 危险开关启动期告警：这些开关都会直接削弱报文安全，误配后运行时没有任何提示。
     */
    private static void warnRiskyConfig(EncryptorConfig config) {
        if (!config.isRequireEncrypted()) {
            logger.warn("encryptor.config.reactive.require-encrypted=false：未带 jwe 载体的请求会被明文放行，"
                + "加密范围出现缺口，请确认是有意为之（默认 true = 未加密请求直接回 failure-status）");
        }
        if (config.getBypass().isRequest() || config.getBypass().isResponse()) {
            logger.warn("encryptor.config.reactive.bypass.request/response 已开启：这是运行期止血开关，"
                + "长期开启等同于关闭报文加密");
        }
        if (config.getMaxResponseSize() <= 0) {
            logger.warn("encryptor.config.reactive.max-response-size<=0：响应缓冲不设上限，"
                + "大响应会全量驻留内存（请配合 black-res-content-type 使用）");
        }
    }

    /**
     * 运行期开关（bypass 热改入口）；使用方注册同类型 bean 即可整体替换。
     */
    @Bean
    @ConditionalOnMissingBean
    public EncryptorRuntime encryptorRuntime(DefaultProtocol protocol) {
        return protocol.runtime();
    }

    private static void logSummary(EncryptorConfig config, DefaultProtocol protocol) {
        StringBuilder kids = new StringBuilder();
        for (KeyMaterialConfig key : config.getKeys()) {
            if (kids.length() > 0) {
                kids.append(", ");
            }
            kids.append(key.getKid())
                .append('(').append(key.getType())
                .append(", fp=").append(fingerprint(protocol.keys().spkiBase64(key.getKid())))
                .append(')');
        }
        logger.info("encryptor v2 协议生效(reactive): activeKid={}, keys=[{}], allowedAlgs={}, allowedEncs={}, ttlMs={}, "
                + "requireEncrypted={}, failureStatus={}, maxRequestSize={}, maxResponseSize={}, "
                + "bypass(req={}, res={}), discovery(enable={}, path={})",
            protocol.keys().activeKid(), kids, protocol.allowedAlgs(), protocol.allowedEncs(), protocol.ttlMillis(),
            config.isRequireEncrypted(), config.getFailureStatus(), config.getMaxRequestSize(), config.getMaxResponseSize(),
            config.getBypass().isRequest(), config.getBypass().isResponse(),
            config.getDiscovery().isEnable(), config.getDiscovery().getPath());
    }

    /** 公钥指纹（SPKI 的 SHA-256 前 6 字节 hex），用于启动摘要与运维核对。 */
    private static String fingerprint(String spkiBase64) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(spkiBase64.getBytes(StandardCharsets.US_ASCII));
            StringBuilder hex = new StringBuilder(12);
            for (int i = 0; i < 6; i++) {
                hex.append(String.format("%02x", digest[i]));
            }
            return hex.toString();
        } catch (Exception e) {
            throw new IllegalStateException("计算公钥指纹失败", e);
        }
    }
}
