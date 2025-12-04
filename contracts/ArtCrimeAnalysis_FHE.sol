// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { FHE, euint32, ebool } from "@fhevm/solidity/lib/FHE.sol";
import { SepoliaConfig } from "@fhevm/solidity/config/ZamaConfig.sol";

contract ArtCrimeAnalysis_FHE is SepoliaConfig {
    struct EncryptedReport {
        uint256 reportId;
        euint32 encryptedSuspectData;
        euint32 encryptedTransactionPattern;
        euint32 encryptedArtworkDetails;
        euint32 encryptedLocationData;
        uint256 timestamp;
        address agency;
    }

    struct CrimeAnalysis {
        euint32 encryptedRiskScore;
        euint32 encryptedNetworkConnections;
        euint32 encryptedPatternMatch;
    }

    struct DecryptedFindings {
        uint32 riskScore;
        uint32 networkConnections;
        uint32 patternMatch;
        bool isRevealed;
    }

    uint256 public reportCount;
    mapping(uint256 => EncryptedReport) public encryptedReports;
    mapping(uint256 => CrimeAnalysis) public crimeAnalyses;
    mapping(uint256 => DecryptedFindings) public decryptedFindings;

    mapping(uint256 => uint256) private requestToReportId;
    
    event ReportSubmitted(uint256 indexed reportId, address indexed agency, uint256 timestamp);
    event AnalysisCompleted(uint256 indexed reportId);
    event FindingsDecrypted(uint256 indexed reportId);

    function registerAgency(address agency) public returns (uint256) {
        reportCount += 1;
        return reportCount;
    }

    function submitEncryptedReport(
        euint32 encryptedSuspectData,
        euint32 encryptedTransactionPattern,
        euint32 encryptedArtworkDetails,
        euint32 encryptedLocationData,
        address agency
    ) public {
        uint256 reportId = registerAgency(agency);
        
        encryptedReports[reportId] = EncryptedReport({
            reportId: reportId,
            encryptedSuspectData: encryptedSuspectData,
            encryptedTransactionPattern: encryptedTransactionPattern,
            encryptedArtworkDetails: encryptedArtworkDetails,
            encryptedLocationData: encryptedLocationData,
            timestamp: block.timestamp,
            agency: agency
        });

        analyzeCrimePattern(reportId);
        emit ReportSubmitted(reportId, agency, block.timestamp);
    }

    function analyzeCrimePattern(uint256 reportId) private {
        EncryptedReport storage report = encryptedReports[reportId];
        
        crimeAnalyses[reportId] = CrimeAnalysis({
            encryptedRiskScore: FHE.add(
                FHE.mul(report.encryptedSuspectData, FHE.asEuint32(3)),
                FHE.div(report.encryptedTransactionPattern, FHE.asEuint32(2))
            ),
            encryptedNetworkConnections: FHE.mul(
                report.encryptedLocationData,
                FHE.asEuint32(5)
            ),
            encryptedPatternMatch: FHE.div(
                FHE.add(report.encryptedArtworkDetails, report.encryptedTransactionPattern),
                FHE.asEuint32(2)
            )
        });

        decryptedFindings[reportId] = DecryptedFindings({
            riskScore: 0,
            networkConnections: 0,
            patternMatch: 0,
            isRevealed: false
        });

        emit AnalysisCompleted(reportId);
    }

    function requestFindingsDecryption(uint256 reportId) public {
        require(msg.sender == encryptedReports[reportId].agency, "Not authorized agency");
        require(!decryptedFindings[reportId].isRevealed, "Already decrypted");

        CrimeAnalysis storage analysis = crimeAnalyses[reportId];
        
        bytes32[] memory ciphertexts = new bytes32[](3);
        ciphertexts[0] = FHE.toBytes32(analysis.encryptedRiskScore);
        ciphertexts[1] = FHE.toBytes32(analysis.encryptedNetworkConnections);
        ciphertexts[2] = FHE.toBytes32(analysis.encryptedPatternMatch);
        
        uint256 reqId = FHE.requestDecryption(ciphertexts, this.decryptFindings.selector);
        requestToReportId[reqId] = reportId;
    }

    function decryptFindings(
        uint256 requestId,
        bytes memory cleartexts,
        bytes memory proof
    ) public {
        uint256 reportId = requestToReportId[requestId];
        require(reportId != 0, "Invalid request");

        DecryptedFindings storage findings = decryptedFindings[reportId];
        require(!findings.isRevealed, "Already decrypted");

        FHE.checkSignatures(requestId, cleartexts, proof);

        (uint32 riskScore, uint32 connections, uint32 patternMatch) = 
            abi.decode(cleartexts, (uint32, uint32, uint32));
        
        findings.riskScore = riskScore;
        findings.networkConnections = connections;
        findings.patternMatch = patternMatch;
        findings.isRevealed = true;

        emit FindingsDecrypted(reportId);
    }

    function requestReportDecryption(uint256 reportId) public {
        require(msg.sender == encryptedReports[reportId].agency, "Not authorized agency");
        
        EncryptedReport storage report = encryptedReports[reportId];
        
        bytes32[] memory ciphertexts = new bytes32[](4);
        ciphertexts[0] = FHE.toBytes32(report.encryptedSuspectData);
        ciphertexts[1] = FHE.toBytes32(report.encryptedTransactionPattern);
        ciphertexts[2] = FHE.toBytes32(report.encryptedArtworkDetails);
        ciphertexts[3] = FHE.toBytes32(report.encryptedLocationData);
        
        FHE.requestDecryption(ciphertexts, this.decryptReport.selector);
    }

    function decryptReport(
        uint256 requestId,
        bytes memory cleartexts,
        bytes memory proof
    ) public {
        FHE.checkSignatures(requestId, cleartexts, proof);
        (uint32 suspectData, uint32 transactions, uint32 artwork, uint32 location) = 
            abi.decode(cleartexts, (uint32, uint32, uint32, uint32));
        // Process decrypted report as needed
    }

    function getReportCount() public view returns (uint256) {
        return reportCount;
    }
}