import React, { createContext, useContext, useState, useEffect } from 'react';
import { AWSAccount, ScanResult } from '../types';
import { accountsApi } from '../services/api';

interface AccountContextType {
  accounts: AWSAccount[];
  selectedAccount: AWSAccount | null;
  latestScan: ScanResult | null;
  scans: ScanResult[];
  isLoading: boolean;
  selectAccount: (accountId: number) => void;
  refresh: () => Promise<void>;
}

const AccountContext = createContext<AccountContextType | undefined>(undefined);

export const AccountProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [accounts, setAccounts] = useState<AWSAccount[]>([]);
  const [selectedAccount, setSelectedAccount] = useState<AWSAccount | null>(null);
  const [scans, setScans] = useState<ScanResult[]>([]);
  const [latestScan, setLatestScan] = useState<ScanResult | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  const fetchAccounts = async () => {
    try {
      setIsLoading(true);
      const data = await accountsApi.getAccounts();
      setAccounts(data);
      
      // Auto-select first account if nothing selected or current selected doesn't exist anymore
      if (data.length > 0) {
        const storedId = localStorage.getItem('selectedAccountId');
        const defaultAcct = data.find((a: any) => a.id === Number(storedId)) || data[0];
        setSelectedAccount(defaultAcct);
        localStorage.setItem('selectedAccountId', defaultAcct.id.toString());
      } else {
        setSelectedAccount(null);
        setScans([]);
        setLatestScan(null);
      }
    } catch (error) {
      console.error('Failed to load AWS accounts:', error);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchAccounts();
  }, []);

  useEffect(() => {
    const fetchScans = async () => {
      if (!selectedAccount) return;
      try {
        const scanData = await accountsApi.getScans(selectedAccount.id);
        setScans(scanData);
        // Find latest completed scan
        const completed = scanData.find((s: any) => s.status === 'completed');
        setLatestScan(completed || scanData[0] || null);
      } catch (error) {
        console.error('Failed to load scans:', error);
      }
    };
    fetchScans();
  }, [selectedAccount]);

  const selectAccount = (accountId: number) => {
    const acct = accounts.find(a => a.id === accountId) || null;
    if (acct) {
      setSelectedAccount(acct);
      localStorage.setItem('selectedAccountId', accountId.toString());
    }
  };

  const refresh = async () => {
    await fetchAccounts();
  };

  return (
    <AccountContext.Provider value={{
      accounts,
      selectedAccount,
      latestScan,
      scans,
      isLoading,
      selectAccount,
      refresh
    }}>
      {children}
    </AccountContext.Provider>
  );
};

export const useActiveAccount = () => {
  const context = useContext(AccountContext);
  if (context === undefined) {
    throw new Error('useActiveAccount must be used within an AccountProvider');
  }
  return context;
};
