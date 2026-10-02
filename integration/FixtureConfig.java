import com.blockto.sevpn.protocol.Sha0;
import java.nio.file.*;
import java.security.SecureRandom;
import java.util.Base64;
import java.nio.charset.StandardCharsets;

/** Test-only initializer. Never prints fixture passwords or password hashes. */
class FixtureConfig {
    public static void main(String[] args) throws Exception {
        Path directory = Path.of(args[0]); Files.createDirectories(directory);
        byte[] random = new byte[32]; new SecureRandom().nextBytes(random);
        String admin = Base64.getUrlEncoder().withoutPadding().encodeToString(random);
        new SecureRandom().nextBytes(random);
        String user = Base64.getUrlEncoder().withoutPadding().encodeToString(random);
        Files.writeString(directory.resolve("admin-password.txt"), admin);
        Files.writeString(directory.resolve("password.txt"), user);
        byte[] hash = Sha0.INSTANCE.digest(admin.getBytes(StandardCharsets.UTF_8));
        String config = """
            declare root
            {
                declare ServerConfiguration
                {
                    byte HashedPassword %s
                    uint ServerType 0
                    bool DisableNatTraversal true
                    bool EnableVpnOverDns true
                    bool EnableVpnOverIcmp false
                    bool DisableIPv6Listener true
                    bool DisableJsonRpcWebApi true
                    bool DisableOpenVPNServer true
                    bool DisableSSTPServer true
                }
                declare ListenerList
                {
                    declare Listener0
                    {
                        uint Port 5555
                        bool Enabled true
                    }
                }
                declare LocalBridgeList
                {
                    bool EnableSoftEtherKernelModeDriver false
                }
                declare DDnsClient
                {
                    bool Disabled true
                }
            }
            """.formatted(Base64.getEncoder().encodeToString(hash));
        Files.writeString(directory.resolve("vpn_server.config"), config);
        java.util.Arrays.fill(hash, (byte)0); java.util.Arrays.fill(random, (byte)0);
    }
}
