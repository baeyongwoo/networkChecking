package com.innotium.diagnoser.controller;

import com.innotium.diagnoser.service.DiagnoseResult;
import com.innotium.diagnoser.service.DiagnoseService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@Controller
@RequiredArgsConstructor
public class DiagnoseController {

    private final DiagnoseService diagnoseService;

    @GetMapping("/")
    public String home() {
        return "diagnose";
    }

    @PostMapping("/diagnose-multi")
    public String diagnoseMulti(@RequestParam String target, Model model) {
        List<DiagnoseResult> results = diagnoseService.diagnoseMultiplePorts(target);

        model.addAttribute("target", target);
        model.addAttribute("multiResults", results);

        return "diagnose";
    }



    // 🔍 전체 진단
    @PostMapping("/diagnose")
    public String diagnose(@RequestParam String target,
                           @RequestParam(required = false) Integer port,
                           @RequestParam(required = false) Integer customPort,
                           Model model) {

        int finalPort = (customPort != null) ? customPort : (port != null ? port : 443);

        DiagnoseResult result = diagnoseService.runDiagnosis(target, finalPort);

        model.addAttribute("target", target);
        model.addAttribute("port", finalPort);
        model.addAttribute("customPort", customPort);

        model.addAttribute("result", result.fullOutput);
        model.addAttribute("analysis", result.analysisSummary);

        model.addAttribute("portClosed", !result.portOpen);
        model.addAttribute("sslError", !result.sslValid);
        model.addAttribute("dnsError", !result.dnsSuccess);
        model.addAttribute("httpError", !result.httpSuccess);
        model.addAttribute("pingSuccess", result.pingSuccess);

        // 포트 스캔 결과는 전체 진단에서는 생략
        model.addAttribute("scannedPorts", null);

        return "diagnose";
    }

    // 🧭 포트 스캔만
    @PostMapping("/scan-ports")
    public String scanPorts(@RequestParam String target, Model model) {
        DiagnoseResult scanResult = diagnoseService.scanOnly(target);

        model.addAttribute("target", target);
        model.addAttribute("scannedPorts", scanResult.scannedPorts);
        model.addAttribute("result", scanResult.fullOutput);

        // 분석 결과는 생략
        model.addAttribute("analysis", null);

        // 나머지 진단 항목은 false 또는 null 처리
        model.addAttribute("portClosed", null);
        model.addAttribute("sslError", null);
        model.addAttribute("dnsError", null);
        model.addAttribute("httpError", null);
        model.addAttribute("pingSuccess", null);

        return "diagnose";
    }

    // ✅ Ping 실패 시 IP 설정 창 열기
    @PostMapping("/open-network-settings")
    @ResponseBody
    public void openNetworkSettings() {
        try {
            String os = System.getProperty("os.name").toLowerCase();
            if (os.contains("win")) {
                Runtime.getRuntime().exec("control.exe /name Microsoft.NetworkAndSharingCenter");
            } else if (os.contains("mac")) {
                Runtime.getRuntime().exec("open /System/Library/PreferencePanes/Network.prefPane");
            } else if (os.contains("nix") || os.contains("nux")) {
                Runtime.getRuntime().exec("nm-connection-editor");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // ✅ 포트 닫힘 시 포트 설정 창 열기
    @PostMapping("/open-port-settings")
    @ResponseBody
    public void openPortSettings() {
        try {
            String os = System.getProperty("os.name").toLowerCase();
            if (os.contains("win")) {
                Runtime.getRuntime().exec("control.exe /name Microsoft.WindowsFirewall");
            } else if (os.contains("mac")) {
                Runtime.getRuntime().exec("open /System/Library/PreferencePanes/Security.prefPane");
            } else if (os.contains("nix") || os.contains("nux")) {
                Runtime.getRuntime().exec("gnome-control-center firewall");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}