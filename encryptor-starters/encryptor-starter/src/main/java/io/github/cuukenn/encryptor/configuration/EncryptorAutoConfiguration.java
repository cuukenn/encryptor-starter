package io.github.cuukenn.encryptor.configuration;

import io.github.cuukenn.encryptor.audit.CompositeEncryptorListener;
import io.github.cuukenn.encryptor.audit.EncryptorListener;
import io.github.cuukenn.encryptor.config.EncryptorConfig;
import io.github.cuukenn.encryptor.config.KeyMaterialConfig;
import io.github.cuukenn.encryptor.constant.EncryptorConstant;
import io.github.cuukenn.encryptor.jose.NonceChecker;
import io.github.cuukenn.encryptor.kit.DigestKit;
import io.github.cuukenn.encryptor.exception.EncryptorException;
import io.github.cuukenn.encryptor.protocol.DefaultProtocol;
import io.github.cuukenn.encryptor.protocol.ProtocolAssembler;
import io.github.cuukenn.encryptor.runtime.EncryptorRuntime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.stream.Collectors;

/**
 * v2 协议的通用自动装配：两侧（servlet/reactive）只 {@code new} core 的 {@link DefaultProtocol}，
 * 算法栈不再各写一份；所有非法配置在启动期 fail-fast。
 *
 * @author changgg
 */
@EnableConfigurationProperties(EncryptorConfig.class)
@ConditionalOnProperty(prefix = EncryptorConfig.PREFIX, name = "enable", havingValue = "true", matchIfMissing = true)
@Configuration(proxyBeanMethods = false)
public class EncryptorAutoConfiguration {
    private static final Logger logger = LoggerFactory.getLogger(EncryptorAutoConfiguration.class);

    /**
     * v2 协议栈（密钥库 + JWE 编解码 + 防重放 + 运行期开关）；非法密钥/白名单在这里启动即失败。
     */
    @Bean
    @ConditionalOnMissingBean
    public DefaultProtocol defaultProtocol(EncryptorConfig config, ObjectProvider<EncryptorListener> listener,
                                           ObjectProvider<NonceChecker> nonceChecker) {
        validateFailureStatus(config.getFailureStatus(), "encryptor.config.");
        // 容器里可以有多个监听器（如业务审计 + Micrometer 指标），按 @Order/注册顺序组合后交给协议栈
        EncryptorListener contextListener = CompositeEncryptorListener.of(
            listener.orderedStream().collect(Collectors.toList()));
        DefaultProtocol protocol = ProtocolAssembler.assemble(
            config.getKeys().stream()
                .map(key -> new DefaultProtocol.KeyMaterial(
                    key.getKid(), key.getType(), key.getPrivateKey(), key.getPublicKey()))
                .collect(Collectors.toList()),
            config.getActiveKid(),
            config.getAllowedAlgs(),
            config.getAllowedEncs(),
            config.getTtl() == null ? null : config.getTtl().toMillis(),
            config.getNonceRetention() == null ? null : config.getNonceRetention().toMillis(),
            config.getNonceCapacity(),
            nonceChecker.getIfAvailable(),
            contextListener,
            config.getBypass().isRequest(),
            config.getBypass().isResponse());
        warnRiskyConfig(config);
        logSummary(config, protocol);
        return protocol;
    }

    /**
     * 失败响应状态码必须是合法的 4xx/5xx；写错（如 42）会让失败路径本身抛 IllegalArgumentException。
     */
    private static void validateFailureStatus(int status, String prefix) {
        if (status < 400 || status > 599) {
            throw new EncryptorException(prefix + "failure-status 非法: " + status + "（必须是 400..599）");
        }
    }

    /**
     * 危险开关启动期告警：这些开关都会直接削弱报文安全，误配后运行时没有任何提示。
     */
    private static void warnRiskyConfig(EncryptorConfig config) {
        if (!config.isRequireEncrypted()) {
            logger.warn("encryptor.config.require-encrypted=false：未带 jwe 载体的请求会被明文放行，"
                + "加密范围出现缺口，请确认是有意为之（默认 true = 未加密请求直接回 failure-status）");
        }
        if (config.getBypass().isRequest() || config.getBypass().isResponse()) {
            logger.warn("encryptor.config.bypass.request/response 已开启：这是运行期止血开关，"
                + "长期开启等同于关闭报文加密");
        }
        if (config.getMaxResponseSize() <= 0) {
            logger.warn("encryptor.config.max-response-size<=0：响应缓冲不设上限，"
                + "大响应会全量驻留内存（请配合 skip-res-content-type 使用）");
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
                .append(", fp=").append(DigestKit.fingerprint(protocol.keys().spkiBase64(key.getKid())))
                .append(')');
        }
        logger.info("encryptor v2 协议生效: activeKid={}, keys=[{}], allowedAlgs={}, allowedEncs={}, ttlMs={}, "
                + "requireEncrypted={}, failureStatus={}, maxRequestSize={}, maxResponseSize={}, "
                + "bypass(req={}, res={}), discovery(enable={}, path={})",
            protocol.keys().activeKid(), kids, protocol.allowedAlgs(), protocol.allowedEncs(), protocol.ttlMillis(),
            config.isRequireEncrypted(), config.getFailureStatus(), config.getMaxRequestSize(), config.getMaxResponseSize(),
            config.getBypass().isRequest(), config.getBypass().isResponse(),
            config.getDiscovery().isEnable(), config.getDiscovery().getPath());
    }
}
