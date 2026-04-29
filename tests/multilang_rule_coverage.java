import java.security.MessageDigest;
import javax.net.ssl.HttpsURLConnection;

class MultiLangJavaCoverage {
    void test(String cmd) throws Exception {
        Runtime.getRuntime().exec(cmd);
        MessageDigest.getInstance("MD5");
        HttpsURLConnection conn = null;
        conn.setHostnameVerifier((host, session) -> true);
    }
}
