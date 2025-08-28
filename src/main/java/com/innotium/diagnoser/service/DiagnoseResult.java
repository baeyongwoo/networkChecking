package com.innotium.diagnoser.service;

import java.util.List;

public class DiagnoseResult {
    public boolean dnsSuccess;
    public boolean pingSuccess;
    public boolean portOpen;
    public boolean sslValid = true; // 기본값 true
    public boolean httpSuccess = true; // 기본값 true
    public boolean authFailed = false;
    public String serverType;
    public String pageTitle;
    public long responseTimeMs;

    public String fullOutput;
    public String analysisSummary;
    public List<Integer> scannedPorts;
    public int port; // 분석 대상 포트 번호
    public String serviceName;
    public String resolutionHint;
    public String riskHint;
}