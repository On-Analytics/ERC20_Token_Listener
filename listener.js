
require('dotenv').config();
const { Alchemy, Network } = require('alchemy-sdk');
const { ethers } = require('ethers');
const { createClient } = require('@supabase/supabase-js');

// Initialize Supabase client
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

const NETWORKS = [
  {
    name: 'ethereum',
    settings: {
      apiKey: process.env.ALCHEMY_API_KEY,
      network: Network.ETH_MAINNET,
    }
  },
  {
    name: 'base',
    settings: {
      apiKey: process.env.BASE_ALCHEMY_API_KEY,
      network: Network.BASE_MAINNET,
    }
  }
];

const alchemyInstances = NETWORKS.map(n => ({
  name: n.name,
  alchemy: new Alchemy(n.settings)
}));

const ERC20_ABI = [
  "function name() view returns (string)",
  "function symbol() view returns (string)",
  "function decimals() view returns (uint8)",
  "function totalSupply() view returns (uint256)"
];

console.log('Listening for new contract deployments on Ethereum and Base using Alchemy SDK...');

for (const { name: chainName, alchemy } of alchemyInstances) {
  alchemy.ws.on('block', async (blockNumber) => {
  try {
    const block = await alchemy.core.getBlockWithTransactions(blockNumber);
    if (!block || !block.transactions) return;

    for (const tx of block.transactions) {
      if (!tx.creates) continue;
      const contractAddress = tx.creates;
      // Use ethers with Alchemy's provider for contract calls
      const contract = new ethers.Contract(contractAddress, ERC20_ABI, alchemy.core); 
      try {
        // Try calling ERC20 functions to verify it's an ERC20
        const [name, symbol, decimals] = await Promise.all([
          contract.name(),
          contract.symbol(),
          contract.decimals()
        ]);
        const creatorAddress = tx.from;
        const createdBlockTimestamp = block.timestamp;
        // Convert UNIX timestamp to ISO 8601 string for datetime storage
        const createdBlockDatetime = new Date(createdBlockTimestamp * 1000).toISOString();
        // Convert decimals to Number in case it's a BigInt
        const safeDecimals = typeof decimals === 'bigint' ? Number(decimals) : decimals;
        const tokenData = {
          contract_address: contractAddress,
          creator_address: creatorAddress,
          created_block_timestamp: createdBlockDatetime,
          name,
          symbol,
          decimals: safeDecimals,
          blockchain: chainName
        };
        console.log('New ERC20 token detected:', tokenData);

        // --- Fraud Detection Integration ---
        const { spawn } = require('child_process');
        const python = spawn('python', ['risk_assessment_bridge.py']);
        let riskResult = '';
        let riskError = '';
        python.stdin.write(JSON.stringify(tokenData));
        python.stdin.end();
        python.stdout.on('data', (data) => {
          riskResult += data.toString();
        });
        python.stderr.on('data', (data) => {
          riskError += data.toString();
        });
        python.on('close', async (code) => {
          if (riskError) {
            console.error('Python risk assessment error:', riskError);
          }
          let riskAssessment = null;
          try {
            riskAssessment = JSON.parse(riskResult);
            console.log('Risk Assessment:', riskAssessment);
          } catch (err) {
            console.error('Failed to parse risk assessment:', err, riskResult);
          }

          // Store in Supabase with risk assessment
          try {
            const insertData = riskAssessment ? {
              ...tokenData,
              risk_score: riskAssessment.risk_score,
              is_suspicious: riskAssessment.is_suspicious,
              risk_indicators: JSON.stringify(riskAssessment.indicators),
              risk_details: JSON.stringify(riskAssessment.details),
              tag_1: riskAssessment.is_suspicious ? 'Phishing' : null
            } : tokenData;
            const { error } = await supabase.from('erc20_tokens').insert([insertData]);
            if (error) {
              console.error('Supabase insert error:', error);
            } else {
              console.log('Saved to Supabase.');
            }
          } catch (dbErr) {
            console.error('Supabase insert exception:', dbErr);
          }
        });
      } catch (e) {
        // Not an ERC20 or missing functions
      }
    }
  } catch (err) {
    console.error('Error processing block:', err);
  }
});
}

process.on('SIGINT', () => {
  console.log('Shutting down listeners...');
  for (const { alchemy } of alchemyInstances) {
    if (alchemy.ws && typeof alchemy.ws.close === 'function') {
      alchemy.ws.close();
    }
  }
  process.exit();
});
