package com.innotium.diagnoser.service;

import org.springframework.stereotype.Component;

@Component
public class DiagnosisEngine {

    public String analyze(DiagnoseResult result, String target, int port) {
        StringBuilder summary = new StringBuilder();

        boolean connected = result.portOpen && result.httpSuccess;

        if (connected) {
            summary.append("✅ 접속 성공\n\n");
            summary.append("→ 분석 결과:\n");
            summary.append("  [✓] DNS 해석 성공\n");
            summary.append("  [✓] Ping 응답 OK\n");
            summary.append("  [✓] 포트 ").append(port).append(" 열림\n");
            summary.append("  [✓] HTTP 응답 정상\n\n");

            summary.append("🖥 서버 종류: ").append(result.serverType != null ? result.serverType : "알 수 없음").append("\n");
            summary.append("📄 페이지 제목: ").append(result.pageTitle != null ? result.pageTitle : "없음").append("\n");
            summary.append("⏱ 응답 속도: ").append(result.responseTimeMs).append("ms\n");

            if (result.responseTimeMs > 2000) {
                summary.append("⚠️ 응답 지연: 서버 부하 또는 네트워크 병목 가능성\n");
            }

        } else {
            summary.append("❌ 접속 실패\n\n");
            summary.append("→ 원인 추정:\n");

            summary.append("  ").append(result.dnsSuccess ? "[✓] DNS 해석 성공\n" : "[✗] DNS 해석 실패\n");
            summary.append("  ").append(result.pingSuccess ? "[✓] Ping 응답 OK\n" : "[✗] Ping 실패\n");

            String portStatus = result.portOpen
                    ? "[✓] 포트 " + port + " 열림\n"
                    : "[✗] 포트 " + port + " 닫힘\n";
            summary.append("  ").append(portStatus);

            if (result.portOpen && !result.httpSuccess) {
                summary.append("  [✗] HTTP 응답 없음 → 서비스 미기동 또는 인증 실패 가능\n");
            }

            if (!result.sslValid && port == 443) {
                summary.append("  [✗] SSL 인증서 오류 → HTTPS 접속 불가\n");
            }

            summary.append("\n⮕ 가능성 있는 원인:\n");

            if (!result.dnsSuccess) {
                summary.append("  - 도메인 이름이 잘못되었거나 DNS 서버에 등록되지 않았습니다.\n");
            } else if (!result.pingSuccess) {
                summary.append("  - 서버가 꺼져 있거나 방화벽에 의해 ICMP가 차단됐을 수 있습니다.\n");
            } else if (!result.portOpen) {
                summary.append("  - 해당 포트에 서비스가 열려 있지 않거나 방화벽에 의해 차단됐을 수 있습니다.\n");
            } else if (!result.httpSuccess) {
                summary.append("  - 웹 서버가 미기동 중이거나 인증 실패로 응답이 거부됐을 수 있습니다.\n");
            }

            if (!result.sslValid && port == 443) {
                summary.append("  - SSL 인증서가 만료되었거나 누락됐을 수 있습니다.\n");
            }

            summary.append("\n🛠 해결 가이드:\n");

            if (!result.portOpen) {
                summary.append("  - 서버의 nginx/apache가 실행 중인지 확인하세요.\n");
                summary.append("  - 방화벽(inbound rules)을 열어주세요.\n");
            }

            if (!result.sslValid && port == 443) {
                summary.append("  - SSL 인증서를 갱신하거나 설치하세요.\n");
                summary.append("  - HTTPS 설정이 웹 서버에 적용되어 있는지 확인하세요.\n");
            }

            if (!result.httpSuccess && result.portOpen) {
                summary.append("  - 인증이 필요한 서비스인지 확인하세요.\n");
                summary.append("  - HTTP 응답 코드 및 로그를 확인하세요.\n");
            }
        }

        return summary.toString();
    }
}