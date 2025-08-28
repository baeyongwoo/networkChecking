package com.innotium.diagnoser.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import javax.net.ssl.*;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.*;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class DiagnoseService {

    private final DiagnosisEngine diagnosisEngine;

    private static final Map<Integer, String> portServiceMap = Map.ofEntries(
            Map.entry(22, "SSH"),
            Map.entry(80, "HTTP"),
            Map.entry(443, "HTTPS"),
            Map.entry(8080, "웹서버 (개발용)"),
            Map.entry(8443, "HTTPS (개발용)"),
            Map.entry(3306, "MySQL"),
            Map.entry(5432, "PostgreSQL"),
            Map.entry(6379, "Redis"),
            Map.entry(27017, "MongoDB"),
            Map.entry(5000, "Flask"),
            Map.entry(8000, "Django"),
            Map.entry(40100, "데모 서버")
    );
    private static final Map<Integer, String> riskyPorts = Map.ofEntries(
            Map.entry(23, "Telnet (암호화되지 않음)"),
            Map.entry(21, "FTP (암호화되지 않음)"),
            Map.entry(445, "SMB (랜섬웨어 공격 대상)"),
            Map.entry(3389, "RDP (원격 데스크탑, 외부 노출 위험)"),
            Map.entry(6379, "Redis (인증 없이 접근 가능)"),
            Map.entry(27017, "MongoDB (기본 설정 시 외부 노출 위험)")
    );

    public DiagnoseResult runDiagnosis(String target, int port) {
        DiagnoseResult res = new DiagnoseResult();
        res.port = port;
        res.serviceName = portServiceMap.getOrDefault(port, "알 수 없음");
        StringBuilder output = new StringBuilder();

        // DNS 해석
        try {
            InetAddress address = InetAddress.getByName(target);
            res.dnsSuccess = true;
            output.append("✅ DNS 해석 성공: ").append(address.getHostAddress()).append("\n\n");
        } catch (Exception e) {
            res.dnsSuccess = false;
            output.append("❌ DNS 해석 실패: ").append(e.getMessage()).append("\n\n");
        }

        // Ping 테스트
        try {
            Process ping = new ProcessBuilder("ping", "-n", "3", target).start();
            BufferedReader reader = new BufferedReader(new InputStreamReader(ping.getInputStream(), "MS949"));
            output.append("📡 Ping 결과:\n");
            String line;
            boolean received = false;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
                if (line.contains("TTL=")) received = true;
            }
            res.pingSuccess = received;
            output.append("\n");
        } catch (Exception e) {
            res.pingSuccess = false;
            output.append("❌ Ping 실패: ").append(e.getMessage()).append("\n\n");
        }

        // 포트 열림 여부
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(target, port), 5000);
            res.portOpen = true;
            output.append("🔓 포트 ").append(port).append(" 열림\n\n");
        } catch (Exception e) {
            res.portOpen = false;
            output.append("🔒 포트 ").append(port).append(" 닫힘\n\n");
            res.resolutionHint = getResolutionHint(port, false, false);
        }

        // SSL 인증서 검사 (HTTPS 포트일 경우)
        if (isHttpsPort(port)) {
            try {
                SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
                SSLSocket sslSocket = (SSLSocket) factory.createSocket(target, port);
                sslSocket.setSoTimeout(5000);
                sslSocket.startHandshake();

                SSLSession session = sslSocket.getSession();
                X509Certificate cert = (X509Certificate) session.getPeerCertificates()[0];

                res.sslValid = true;
                output.append("🔐 SSL 인증서 유효\n");
                output.append("   - 발급자: ").append(cert.getIssuerX500Principal().getName()).append("\n");
                output.append("   - 유효기간: ").append(cert.getNotBefore()).append(" ~ ").append(cert.getNotAfter()).append("\n\n");

            } catch (Exception e) {
                res.sslValid = false;
                output.append("❌ SSL 인증서 오류: ").append(e.getMessage()).append("\n\n");
            }
        }

        // HTTP 응답 분석
        try {
            long start = System.currentTimeMillis();
            String protocol = isHttpsPort(port) ? "https" : "http";
            URL url = new URL(protocol + "://" + target + ":" + port + "/");

            int code;
            String serverType;

            if (protocol.equals("https")) {
                HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
                conn.setConnectTimeout(5000);
                conn.setReadTimeout(5000);
                conn.setRequestMethod("GET");

                code = conn.getResponseCode();
                serverType = conn.getHeaderField("Server");
            } else {
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setConnectTimeout(5000);
                conn.setReadTimeout(5000);
                conn.setRequestMethod("GET");
                conn.setRequestProperty("User-Agent", "Mozilla/5.0");

                code = conn.getResponseCode();
                serverType = conn.getHeaderField("Server");
            }

            res.httpSuccess = (code >= 200 && code < 400);
            res.authFailed = (code == 401 || code == 403);
            res.serverType = serverType;
            res.responseTimeMs = System.currentTimeMillis() - start;

            output.append("🌐 HTTP 응답 코드: ").append(code).append("\n");
            output.append("🖥 서버 종류: ").append(serverType != null ? serverType : "알 수 없음").append("\n");
            output.append("⏱ 응답 속도: ").append(res.responseTimeMs).append("ms\n\n");

        } catch (Exception e) {
            res.httpSuccess = false;
            res.serverType = null;
            output.append("❌ HTTP 요청 실패: ").append(e.getMessage()).append("\n\n");

            if (res.portOpen) {
                res.resolutionHint = getResolutionHint(port, true, false);
            }
        }
        if (res.portOpen && riskyPorts.containsKey(port)) {
            res.riskHint = "⚠️ 보안 경고: " + riskyPorts.get(port) + " 포트가 열려 있습니다. 외부 노출 시 보안 취약점이 발생할 수 있습니다.";
        }

        // 분석 결과 생성
        res.analysisSummary = diagnosisEngine.analyze(res, target, port);
        res.fullOutput = output.toString();

        return res;
    }

    public DiagnoseResult scanOnly(String target) {
        DiagnoseResult res = new DiagnoseResult();
        StringBuilder output = new StringBuilder();

        List<Integer> openPorts = new ArrayList<>();
        int[] scanPorts = {22, 80, 443, 8080, 8443, 3306, 5432, 6379, 40100};

        output.append("🔍 포트 스캔 결과:\n");
        for (int p : scanPorts) {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(target, p), 200);
                openPorts.add(p);
                output.append("✅ 포트 ").append(p).append(" 열림\n");
            } catch (Exception ignored) {
                output.append("🔒 포트 ").append(p).append(" 닫힘\n");
            }
        }

        res.scannedPorts = openPorts;
        res.fullOutput = output.toString();
        return res;
    }

    public List<DiagnoseResult> diagnoseMultiplePorts(String target) {
        List<Integer> scanPorts = List.of(80, 443, 8080, 8443, 3306, 5432, 6379, 40100);
        List<DiagnoseResult> results = new ArrayList<>();

        for (int port : scanPorts) {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(target, port), 200);
                DiagnoseResult res = runDiagnosis(target, port);
                results.add(res);
            } catch (Exception ignored) {
                // 포트 닫힘은 무시
            }
        }

        return results;
    }

    private boolean isHttpsPort(int port) {
        return port == 443 || port == 8443 || port == 9443;
    }

    private String getResolutionHint(int port, boolean portOpen, boolean sslIssue) {
        if (!portOpen) {
            return switch (port) {
                case 22 -> "🔧 SSH 접속 실패: sshd 서비스가 실행 중인지 확인하고, 방화벽에서 22번 포트를 허용하세요.";
                case 80 -> "🌐 웹 서버 접속 실패: Apache/Nginx가 실행 중인지 확인하고, 방화벽에서 80번 포트를 열어주세요.";
                case 443 -> "🔐 HTTPS 접속 실패: SSL 인증서 설치 여부와 443번 포트 방화벽 설정을 확인하세요.";
                case 3306 -> "🗄 MySQL 접속 실패: 외부 접속 허용 여부와 3306번 포트 방화벽 설정을 확인하세요.";
                case 5432 -> "🗄 PostgreSQL 접속 실패: pg_hba.conf 설정과 방화벽을 확인하세요.";
                case 6379 -> "⚠️ Redis 접속 실패: redis.conf에서 bind 설정과 requirepass 여부를 확인하고, 6379번 포트를 허용하세요.";
                case 40100 -> "🧪 데모 서버 접속 실패: 해당 포트가 방화벽에서 허용되어 있는지 확인하고, 서버 애플리케이션이 실행 중인지 확인하세요.";
                default -> "🚫 포트가 닫혀 있습니다. 서버 애플리케이션이 실행 중인지, 방화벽이나 보안 그룹에서 해당 포트가 허용되어 있는지 확인하세요.";
            };
        }

        if (!sslIssue && isHttpsPort(port)) {
            return "🔐 HTTPS 응답 없음: SSL 인증서가 올바르게 설치되어 있는지 확인하고, 웹 서버 설정을 점검하세요.";
        }

        return switch (port) {
            case 80 -> "🌐 HTTP 응답 없음: 웹 서버가 실행 중인지 확인하고, index.html 또는 라우팅 설정을 점검하세요.";
            case 8080, 8443 -> "🧪 개발용 웹 포트 응답 없음: 백엔드 애플리케이션(Spring, Node 등)이 실행 중인지 확인하세요.";
            case 3306 -> "🗄 DB 응답 없음: MySQL이 실행 중인지, 외부 접속이 허용되어 있는지 확인하세요.";
            default -> "🚫 HTTP 응답 없음: 해당 포트에서 웹 애플리케이션이 정상적으로 실행 중인지 확인하고, 방화벽 및 라우팅 설정을 점검하세요.";
        };
    }
}