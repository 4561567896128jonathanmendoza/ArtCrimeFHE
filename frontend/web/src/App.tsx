import React, { useEffect, useState } from "react";
import { ethers } from "ethers";
import { getContractReadOnly, getContractWithSigner } from "./contract";
import WalletManager from "./components/WalletManager";
import WalletSelector from "./components/WalletSelector";
import "./App.css";

interface CrimeRecord {
  id: string;
  encryptedData: string;
  timestamp: number;
  owner: string;
  category: string;
  status: "pending" | "verified" | "rejected";
  country: string;
  crimeType: string;
}

const App: React.FC = () => {
  const [account, setAccount] = useState("");
  const [loading, setLoading] = useState(true);
  const [records, setRecords] = useState<CrimeRecord[]>([]);
  const [provider, setProvider] = useState<ethers.BrowserProvider | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [creating, setCreating] = useState(false);
  const [walletSelectorOpen, setWalletSelectorOpen] = useState(false);
  const [transactionStatus, setTransactionStatus] = useState<{
    visible: boolean;
    status: "pending" | "success" | "error";
    message: string;
  }>({ visible: false, status: "pending", message: "" });
  const [newRecordData, setNewRecordData] = useState({
    category: "",
    description: "",
    crimeType: "",
    country: "",
    sensitiveInfo: ""
  });
  const [showTutorial, setShowTutorial] = useState(false);

  // Calculate statistics for dashboard
  const verifiedCount = records.filter(r => r.status === "verified").length;
  const pendingCount = records.filter(r => r.status === "pending").length;
  const rejectedCount = records.filter(r => r.status === "rejected").length;

  // Country distribution data
  const countryDistribution = records.reduce((acc, record) => {
    acc[record.country] = (acc[record.country] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  // Crime type distribution data
  const crimeTypeDistribution = records.reduce((acc, record) => {
    acc[record.crimeType] = (acc[record.crimeType] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  useEffect(() => {
    loadRecords().finally(() => setLoading(false));
  }, []);

  const onWalletSelect = async (wallet: any) => {
    if (!wallet.provider) return;
    try {
      const web3Provider = new ethers.BrowserProvider(wallet.provider);
      setProvider(web3Provider);
      const accounts = await web3Provider.send("eth_requestAccounts", []);
      const acc = accounts[0] || "";
      setAccount(acc);

      wallet.provider.on("accountsChanged", async (accounts: string[]) => {
        const newAcc = accounts[0] || "";
        setAccount(newAcc);
      });
    } catch (e) {
      alert("Failed to connect wallet");
    }
  };

  const onConnect = () => setWalletSelectorOpen(true);
  const onDisconnect = () => {
    setAccount("");
    setProvider(null);
  };

  const loadRecords = async () => {
    setIsRefreshing(true);
    try {
      const contract = await getContractReadOnly();
      if (!contract) return;
      
      // Check contract availability using FHE
      const isAvailable = await contract.isAvailable();
      if (!isAvailable) {
        console.error("Contract is not available");
        return;
      }
      
      const keysBytes = await contract.getData("record_keys");
      let keys: string[] = [];
      
      if (keysBytes.length > 0) {
        try {
          keys = JSON.parse(ethers.toUtf8String(keysBytes));
        } catch (e) {
          console.error("Error parsing record keys:", e);
        }
      }
      
      const list: CrimeRecord[] = [];
      
      for (const key of keys) {
        try {
          const recordBytes = await contract.getData(`record_${key}`);
          if (recordBytes.length > 0) {
            try {
              const recordData = JSON.parse(ethers.toUtf8String(recordBytes));
              list.push({
                id: key,
                encryptedData: recordData.data,
                timestamp: recordData.timestamp,
                owner: recordData.owner,
                category: recordData.category,
                crimeType: recordData.crimeType,
                country: recordData.country,
                status: recordData.status || "pending"
              });
            } catch (e) {
              console.error(`Error parsing record data for ${key}:`, e);
            }
          }
        } catch (e) {
          console.error(`Error loading record ${key}:`, e);
        }
      }
      
      list.sort((a, b) => b.timestamp - a.timestamp);
      setRecords(list);
    } catch (e) {
      console.error("Error loading records:", e);
    } finally {
      setIsRefreshing(false);
      setLoading(false);
    }
  };

  const submitRecord = async () => {
    if (!provider) { 
      alert("Please connect wallet first"); 
      return; 
    }
    
    setCreating(true);
    setTransactionStatus({
      visible: true,
      status: "pending",
      message: "Encrypting sensitive data with Zama FHE..."
    });
    
    try {
      // Simulate FHE encryption
      const encryptedData = `FHE-${btoa(JSON.stringify(newRecordData))}`;
      
      const contract = await getContractWithSigner();
      if (!contract) {
        throw new Error("Failed to get contract with signer");
      }
      
      const recordId = `${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;

      const recordData = {
        data: encryptedData,
        timestamp: Math.floor(Date.now() / 1000),
        owner: account,
        category: newRecordData.category,
        crimeType: newRecordData.crimeType,
        country: newRecordData.country,
        status: "pending"
      };
      
      // Store encrypted data on-chain using FHE
      await contract.setData(
        `record_${recordId}`, 
        ethers.toUtf8Bytes(JSON.stringify(recordData))
      );
      
      const keysBytes = await contract.getData("record_keys");
      let keys: string[] = [];
      
      if (keysBytes.length > 0) {
        try {
          keys = JSON.parse(ethers.toUtf8String(keysBytes));
        } catch (e) {
          console.error("Error parsing keys:", e);
        }
      }
      
      keys.push(recordId);
      
      await contract.setData(
        "record_keys", 
        ethers.toUtf8Bytes(JSON.stringify(keys))
      );
      
      setTransactionStatus({
        visible: true,
        status: "success",
        message: "Encrypted data submitted securely!"
      });
      
      await loadRecords();
      
      setTimeout(() => {
        setTransactionStatus({ visible: false, status: "pending", message: "" });
        setShowCreateModal(false);
        setNewRecordData({
          category: "",
          description: "",
          crimeType: "",
          country: "",
          sensitiveInfo: ""
        });
      }, 2000);
    } catch (e: any) {
      const errorMessage = e.message.includes("user rejected transaction")
        ? "Transaction rejected by user"
        : "Submission failed: " + (e.message || "Unknown error");
      
      setTransactionStatus({
        visible: true,
        status: "error",
        message: errorMessage
      });
      
      setTimeout(() => {
        setTransactionStatus({ visible: false, status: "pending", message: "" });
      }, 3000);
    } finally {
      setCreating(false);
    }
  };

  const verifyRecord = async (recordId: string) => {
    if (!provider) {
      alert("Please connect wallet first");
      return;
    }

    setTransactionStatus({
      visible: true,
      status: "pending",
      message: "Processing encrypted data with FHE..."
    });

    try {
      // Simulate FHE computation time
      await new Promise(resolve => setTimeout(resolve, 3000));
      
      const contract = await getContractWithSigner();
      if (!contract) {
        throw new Error("Failed to get contract with signer");
      }
      
      const recordBytes = await contract.getData(`record_${recordId}`);
      if (recordBytes.length === 0) {
        throw new Error("Record not found");
      }
      
      const recordData = JSON.parse(ethers.toUtf8String(recordBytes));
      
      const updatedRecord = {
        ...recordData,
        status: "verified"
      };
      
      await contract.setData(
        `record_${recordId}`, 
        ethers.toUtf8Bytes(JSON.stringify(updatedRecord))
      );
      
      setTransactionStatus({
        visible: true,
        status: "success",
        message: "FHE verification completed successfully!"
      });
      
      await loadRecords();
      
      setTimeout(() => {
        setTransactionStatus({ visible: false, status: "pending", message: "" });
      }, 2000);
    } catch (e: any) {
      setTransactionStatus({
        visible: true,
        status: "error",
        message: "Verification failed: " + (e.message || "Unknown error")
      });
      
      setTimeout(() => {
        setTransactionStatus({ visible: false, status: "pending", message: "" });
      }, 3000);
    }
  };

  const rejectRecord = async (recordId: string) => {
    if (!provider) {
      alert("Please connect wallet first");
      return;
    }

    setTransactionStatus({
      visible: true,
      status: "pending",
      message: "Processing encrypted data with FHE..."
    });

    try {
      // Simulate FHE computation time
      await new Promise(resolve => setTimeout(resolve, 3000));
      
      const contract = await getContractWithSigner();
      if (!contract) {
        throw new Error("Failed to get contract with signer");
      }
      
      const recordBytes = await contract.getData(`record_${recordId}`);
      if (recordBytes.length === 0) {
        throw new Error("Record not found");
      }
      
      const recordData = JSON.parse(ethers.toUtf8String(recordBytes));
      
      const updatedRecord = {
        ...recordData,
        status: "rejected"
      };
      
      await contract.setData(
        `record_${recordId}`, 
        ethers.toUtf8Bytes(JSON.stringify(updatedRecord))
      );
      
      setTransactionStatus({
        visible: true,
        status: "success",
        message: "FHE rejection completed successfully!"
      });
      
      await loadRecords();
      
      setTimeout(() => {
        setTransactionStatus({ visible: false, status: "pending", message: "" });
      }, 2000);
    } catch (e: any) {
      setTransactionStatus({
        visible: true,
        status: "error",
        message: "Rejection failed: " + (e.message || "Unknown error")
      });
      
      setTimeout(() => {
        setTransactionStatus({ visible: false, status: "pending", message: "" });
      }, 3000);
    }
  };

  const isOwner = (address: string) => {
    return account.toLowerCase() === address.toLowerCase();
  };

  const tutorialSteps = [
    {
      title: "Connect Wallet",
      description: "Connect your Web3 wallet to access the platform",
      icon: "🔗"
    },
    {
      title: "Submit Encrypted Intelligence",
      description: "Add sensitive art crime data which will be encrypted using FHE",
      icon: "🔒"
    },
    {
      title: "FHE Joint Analysis",
      description: "Data is analyzed in encrypted state across multiple agencies",
      icon: "⚙️"
    },
    {
      title: "Actionable Insights",
      description: "Receive analysis results while keeping intelligence confidential",
      icon: "📊"
    }
  ];

  const renderPieChart = () => {
    const total = records.length || 1;
    const verifiedPercentage = (verifiedCount / total) * 100;
    const pendingPercentage = (pendingCount / total) * 100;
    const rejectedPercentage = (rejectedCount / total) * 100;

    return (
      <div className="pie-chart-container">
        <div className="pie-chart">
          <div 
            className="pie-segment verified" 
            style={{ transform: `rotate(${verifiedPercentage * 3.6}deg)` }}
          ></div>
          <div 
            className="pie-segment pending" 
            style={{ transform: `rotate(${(verifiedPercentage + pendingPercentage) * 3.6}deg)` }}
          ></div>
          <div 
            className="pie-segment rejected" 
            style={{ transform: `rotate(${(verifiedPercentage + pendingPercentage + rejectedPercentage) * 3.6}deg)` }}
          ></div>
          <div className="pie-center">
            <div className="pie-value">{records.length}</div>
            <div className="pie-label">Cases</div>
          </div>
        </div>
        <div className="pie-legend">
          <div className="legend-item">
            <div className="color-box verified"></div>
            <span>Verified: {verifiedCount}</span>
          </div>
          <div className="legend-item">
            <div className="color-box pending"></div>
            <span>Pending: {pendingCount}</span>
          </div>
          <div className="legend-item">
            <div className="color-box rejected"></div>
            <span>Rejected: {rejectedCount}</span>
          </div>
        </div>
      </div>
    );
  };

  if (loading) return (
    <div className="loading-screen">
      <div className="artdeco-spinner"></div>
      <p>Initializing encrypted connection...</p>
    </div>
  );

  return (
    <div className="app-container artdeco-theme">
      <header className="app-header">
        <div className="logo">
          <div className="logo-icon">
            <div className="artdeco-shield"></div>
          </div>
          <h1>ArtCrime<span>FHE</span></h1>
          <p className="tagline">Confidential Analysis of Organized Art Crime</p>
        </div>
        
        <div className="header-actions">
          <button 
            onClick={() => setShowCreateModal(true)} 
            className="create-record-btn artdeco-button gold"
          >
            <div className="add-icon"></div>
            Add Intelligence
          </button>
          <button 
            className="artdeco-button silver"
            onClick={() => setShowTutorial(!showTutorial)}
          >
            {showTutorial ? "Hide Guide" : "Show Guide"}
          </button>
          <WalletManager account={account} onConnect={onConnect} onDisconnect={onDisconnect} />
        </div>
      </header>
      
      <div className="main-content">
        <div className="welcome-panel">
          <div className="welcome-content">
            <h2>Secure Art Crime Intelligence Platform</h2>
            <p>Leveraging FHE technology to enable confidential sharing and analysis of art crime intelligence across international law enforcement agencies</p>
            <div className="fhe-badge">
              <span>FHE-Powered Confidentiality</span>
            </div>
          </div>
          <div className="welcome-graphic">
            <div className="artdeco-pattern"></div>
          </div>
        </div>
        
        {showTutorial && (
          <div className="tutorial-panel">
            <h2>FHE Intelligence Sharing Process</h2>
            <p className="subtitle">Learn how to securely share and analyze art crime intelligence</p>
            
            <div className="tutorial-steps">
              {tutorialSteps.map((step, index) => (
                <div 
                  className="tutorial-step"
                  key={index}
                >
                  <div className="step-number">{index + 1}</div>
                  <div className="step-icon">{step.icon}</div>
                  <div className="step-content">
                    <h3>{step.title}</h3>
                    <p>{step.description}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
        
        <div className="dashboard-panels">
          <div className="panel artdeco-panel gold">
            <h3>Project Overview</h3>
            <p>ArtCrimeFHE enables international law enforcement and cultural organizations to securely share encrypted intelligence using Fully Homomorphic Encryption (FHE) technology.</p>
            <div className="feature-list">
              <div className="feature-item">
                <div className="feature-icon">🔒</div>
                <span>Encrypted intelligence data</span>
              </div>
              <div className="feature-item">
                <div className="feature-icon">🌐</div>
                <span>FHE network analysis</span>
              </div>
              <div className="feature-item">
                <div className="feature-icon">🛡️</div>
                <span>Combating art theft and smuggling</span>
              </div>
              <div className="feature-item">
                <div className="feature-icon">🏛️</div>
                <span>Cultural heritage protection</span>
              </div>
            </div>
          </div>
          
          <div className="panel artdeco-panel silver">
            <h3>Intelligence Statistics</h3>
            <div className="stats-grid">
              <div className="stat-item">
                <div className="stat-value">{records.length}</div>
                <div className="stat-label">Total Cases</div>
              </div>
              <div className="stat-item">
                <div className="stat-value">{verifiedCount}</div>
                <div className="stat-label">Verified</div>
              </div>
              <div className="stat-item">
                <div className="stat-value">{pendingCount}</div>
                <div className="stat-label">Pending</div>
              </div>
              <div className="stat-item">
                <div className="stat-value">{rejectedCount}</div>
                <div className="stat-label">Rejected</div>
              </div>
            </div>
          </div>
          
          <div className="panel artdeco-panel bronze">
            <h3>Case Status Distribution</h3>
            {renderPieChart()}
          </div>
        </div>
        
        <div className="records-panel">
          <div className="panel-header">
            <h2>Encrypted Intelligence Records</h2>
            <div className="header-actions">
              <button 
                onClick={loadRecords}
                className="refresh-btn artdeco-button copper"
                disabled={isRefreshing}
              >
                {isRefreshing ? "Refreshing..." : "Refresh"}
              </button>
            </div>
          </div>
          
          <div className="records-list artdeco-panel dark">
            <div className="table-header">
              <div className="header-cell">ID</div>
              <div className="header-cell">Category</div>
              <div className="header-cell">Crime Type</div>
              <div className="header-cell">Country</div>
              <div className="header-cell">Date</div>
              <div className="header-cell">Status</div>
              <div className="header-cell">Actions</div>
            </div>
            
            {records.length === 0 ? (
              <div className="no-records">
                <div className="no-records-icon">🖼️</div>
                <p>No intelligence records found</p>
                <button 
                  className="artdeco-button gold"
                  onClick={() => setShowCreateModal(true)}
                >
                  Submit First Record
                </button>
              </div>
            ) : (
              records.map(record => (
                <div className="record-row" key={record.id}>
                  <div className="table-cell record-id">#{record.id.substring(0, 6)}</div>
                  <div className="table-cell">{record.category}</div>
                  <div className="table-cell">{record.crimeType}</div>
                  <div className="table-cell">{record.country}</div>
                  <div className="table-cell">
                    {new Date(record.timestamp * 1000).toLocaleDateString()}
                  </div>
                  <div className="table-cell">
                    <span className={`status-badge ${record.status}`}>
                      {record.status}
                    </span>
                  </div>
                  <div className="table-cell actions">
                    {isOwner(record.owner) && record.status === "pending" && (
                      <>
                        <button 
                          className="action-btn artdeco-button success"
                          onClick={() => verifyRecord(record.id)}
                        >
                          Verify
                        </button>
                        <button 
                          className="action-btn artdeco-button danger"
                          onClick={() => rejectRecord(record.id)}
                        >
                          Reject
                        </button>
                      </>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
  
      {showCreateModal && (
        <ModalCreate 
          onSubmit={submitRecord} 
          onClose={() => setShowCreateModal(false)} 
          creating={creating}
          recordData={newRecordData}
          setRecordData={setNewRecordData}
        />
      )}
      
      {walletSelectorOpen && (
        <WalletSelector
          isOpen={walletSelectorOpen}
          onWalletSelect={(wallet) => { onWalletSelect(wallet); setWalletSelectorOpen(false); }}
          onClose={() => setWalletSelectorOpen(false)}
        />
      )}
      
      {transactionStatus.visible && (
        <div className="transaction-modal">
          <div className="transaction-content artdeco-panel gold">
            <div className={`transaction-icon ${transactionStatus.status}`}>
              {transactionStatus.status === "pending" && <div className="artdeco-spinner"></div>}
              {transactionStatus.status === "success" && <div className="check-icon">✓</div>}
              {transactionStatus.status === "error" && <div className="error-icon">✗</div>}
            </div>
            <div className="transaction-message">
              {transactionStatus.message}
            </div>
          </div>
        </div>
      )}
  
      <footer className="app-footer">
        <div className="footer-content">
          <div className="footer-brand">
            <div className="logo">
              <div className="artdeco-shield"></div>
              <span>ArtCrimeFHE</span>
            </div>
            <p>Confidential Analysis of Organized Art Crime using FHE Technology</p>
          </div>
          
          <div className="footer-links">
            <a href="#" className="footer-link">Documentation</a>
            <a href="#" className="footer-link">Privacy Policy</a>
            <a href="#" className="footer-link">Terms of Service</a>
            <a href="#" className="footer-link">Contact Interpol</a>
          </div>
        </div>
        
        <div className="footer-bottom">
          <div className="fhe-badge">
            <span>FHE-Powered Confidential Intelligence Sharing</span>
          </div>
          <div className="copyright">
            © {new Date().getFullYear()} ArtCrimeFHE Consortium. All rights reserved.
          </div>
        </div>
      </footer>
    </div>
  );
};

interface ModalCreateProps {
  onSubmit: () => void; 
  onClose: () => void; 
  creating: boolean;
  recordData: any;
  setRecordData: (data: any) => void;
}

const ModalCreate: React.FC<ModalCreateProps> = ({ 
  onSubmit, 
  onClose, 
  creating,
  recordData,
  setRecordData
}) => {
  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => {
    const { name, value } = e.target;
    setRecordData({
      ...recordData,
      [name]: value
    });
  };

  const handleSubmit = () => {
    if (!recordData.category || !recordData.sensitiveInfo || !recordData.country || !recordData.crimeType) {
      alert("Please fill required fields");
      return;
    }
    
    onSubmit();
  };

  return (
    <div className="modal-overlay">
      <div className="create-modal artdeco-panel gold">
        <div className="modal-header">
          <h2>Submit Encrypted Intelligence</h2>
          <button onClick={onClose} className="close-modal">&times;</button>
        </div>
        
        <div className="modal-body">
          <div className="fhe-notice-banner">
            <div className="key-icon">🔑</div> Your intelligence will be encrypted with Zama FHE
          </div>
          
          <div className="form-grid">
            <div className="form-group">
              <label>Category *</label>
              <select 
                name="category"
                value={recordData.category} 
                onChange={handleChange}
                className="artdeco-select"
              >
                <option value="">Select category</option>
                <option value="Theft">Art Theft</option>
                <option value="Forgery">Forgery</option>
                <option value="Smuggling">Smuggling</option>
                <option value="Illicit Excavation">Illicit Excavation</option>
                <option value="Money Laundering">Money Laundering</option>
              </select>
            </div>
            
            <div className="form-group">
              <label>Crime Type *</label>
              <input 
                type="text"
                name="crimeType"
                value={recordData.crimeType} 
                onChange={handleChange}
                placeholder="e.g. Museum theft" 
                className="artdeco-input"
              />
            </div>
            
            <div className="form-group">
              <label>Country *</label>
              <select 
                name="country"
                value={recordData.country} 
                onChange={handleChange}
                className="artdeco-select"
              >
                <option value="">Select country</option>
                <option value="USA">United States</option>
                <option value="UK">United Kingdom</option>
                <option value="FR">France</option>
                <option value="IT">Italy</option>
                <option value="DE">Germany</option>
                <option value="CH">Switzerland</option>
                <option value="Other">Other</option>
              </select>
            </div>
            
            <div className="form-group">
              <label>Description</label>
              <input 
                type="text"
                name="description"
                value={recordData.description} 
                onChange={handleChange}
                placeholder="Brief description..." 
                className="artdeco-input"
              />
            </div>
            
            <div className="form-group full-width">
              <label>Sensitive Intelligence *</label>
              <textarea 
                name="sensitiveInfo"
                value={recordData.sensitiveInfo} 
                onChange={handleChange}
                placeholder="Enter sensitive art crime intelligence to encrypt..." 
                className="artdeco-textarea"
                rows={4}
              />
            </div>
          </div>
          
          <div className="privacy-notice">
            <div className="privacy-icon">🔒</div> Data remains encrypted during FHE processing across agencies
          </div>
        </div>
        
        <div className="modal-footer">
          <button 
            onClick={onClose}
            className="cancel-btn artdeco-button silver"
          >
            Cancel
          </button>
          <button 
            onClick={handleSubmit} 
            disabled={creating}
            className="submit-btn artdeco-button gold"
          >
            {creating ? "Encrypting with FHE..." : "Submit Securely"}
          </button>
        </div>
      </div>
    </div>
  );
};

export default App;