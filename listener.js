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
      apiKey: process.env.ALCHEMY_API_KEY,
      network: Network.BASE_MAINNET,
    }
  },
  {
    name: 'polygon',
    settings: {
      apiKey: process.env.ALCHEMY_API_KEY,
      network: Network.MATIC_MAINNET,
    }
  },
  {
    name: 'arbitrum',
    settings: {
      apiKey: process.env.ALCHEMY_API_KEY,
      network: Network.ARB_MAINNET,
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

// Validate network configurations on startup
async function validateNetworkConfigs() {
  console.log('\n=== Validating Network Configurations ===');
  for (const { name: chainName, alchemy } of alchemyInstances) {
    try {
      const network = await alchemy.core.getNetwork();
      const latestBlock = await alchemy.core.getBlockNumber();
      console.log(`${chainName.toUpperCase()}:`);
      console.log(`  - Network ID: ${network.chainId}`);
      console.log(`  - Network Name: ${network.name}`);
      console.log(`  - Latest Block: ${latestBlock}`);
      console.log(`  - API Key (first 10 chars): ${alchemy.config.apiKey?.substr(0, 10)}...`);
    } catch (error) {
      console.error(`❌ Failed to validate ${chainName} network:`, error.message);
    }
  }
  console.log('=== Validation Complete ===\n');
}

validateNetworkConfigs();

console.log('Listening for new contract deployments on Ethereum, Base, and Polygon using Alchemy SDK...');

// Track processed contract addresses per network
const processedContracts = {};
// Each network's listener is fully independent; only processes tokens detected on its own chain.
for (const { name: chainName, alchemy } of alchemyInstances) {
  if (!processedContracts[chainName]) processedContracts[chainName] = new Set();

  // Listen for new blocks on this specific network only
  alchemy.ws.on('block', async (blockNumber) => {
  try {
    const block = await alchemy.core.getBlockWithTransactions(blockNumber);
    if (!block || !block.transactions) return;

    for (const tx of block.transactions) {
      if (!tx.creates) continue;
      const contractAddress = tx.creates;
      // Prevent duplicate processing for this network
      if (processedContracts[chainName].has(contractAddress)) continue;
      processedContracts[chainName].add(contractAddress);
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
        // Each network only processes its own tokens. No cross-chain searching or processing.
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
        python.stdin.write(JSON.stringify([tokenData])); // Wrap in array for Python
        python.stdin.end();
        python.stdout.on('data', (data) => {
          riskResult += data.toString();
        });
        python.stderr.on('data', (data) => {
          riskError += data.toString();
        });
        python.on('close', async (code) => {
          // Log stderr output but don't treat it as an error
          // Our Python script now sends informational logs to stderr
          if (riskError) {
            console.log('Python stderr output:', riskError);
          }
          
          let riskAssessment = null;
          try {
            // Always try to parse if we have a non-empty result
            // The actual errors would cause the Python script to exit with non-zero code
            if (riskResult && riskResult.trim()) {
              riskAssessment = JSON.parse(riskResult);
              console.log('Risk Assessment:', riskAssessment);
            } else if (code !== 0) {
              // Only skip parsing if the Python script actually failed (non-zero exit code)
              console.log('Skipping risk assessment parsing due to Python error (exit code:', code, ')');
            }
          } catch (err) {
            console.error('Failed to parse risk assessment:', err, riskResult);
          }

          // Store in Supabase with risk assessment
          try {
            // Always save the token data, with risk assessment if available
            let insertData = { ...tokenData };
            
            // Add risk assessment data if available
            if (riskAssessment && Array.isArray(riskAssessment) && riskAssessment.length > 0) {
              // The Python script returns an array, so we need to get the first item
              const assessment = riskAssessment[0];
              
              // Map all the fields from the Python risk assessment to the Supabase schema
              insertData = {
                ...insertData,
                // Using only columns that exist in the table schema
                risk_category: assessment.risk_category || 'unknown',
                fraud_type: assessment.fraud_type || 'unknown',
                // Store all details in the detection_details column
                detection_details: JSON.stringify({
                  phishing_indicators: assessment.phishing_indicators || [],
                  urls_found: assessment.urls_found || [],
                  money_amounts: assessment.money_amounts || [],
                  details: assessment.details || {}
                })
              };
              
              console.log(`Preparing to save with fraud_type=${assessment.fraud_type}, risk_category=${assessment.risk_category}`);
            }
            
            // Upsert the token data into Supabase using the unique constraint
            const { error } = await supabase.from('erc20_tokens').upsert([insertData], {
              onConflict: 'contract_address,blockchain'
            });
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