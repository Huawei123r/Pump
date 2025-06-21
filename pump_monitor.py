# pump_monitor.py (Full Code - Latest Version)

import asyncio
import json
import base64
from solana.rpc.websocket_client import SolanaWsClient
from solders.pubkey import Pubkey
from dotenv import load_dotenv
import os
from anchorpy import Program, Idl
from pathlib import Path

# Load environment variables from .env file
load_dotenv()

# --- Configuration ---
# Now load the WSS_URL from your .env file
WSS_URL = os.getenv("SOLANA_WSS_URL")

# Fallback in case .env isn't set (though it should be for this example)
if not WSS_URL:
    print("Warning: SOLANA_WSS_URL not found in .env. Using default public Devnet URL.")
    WSS_URL = "wss://api.devnet.solana.com/"

PUMPFUN_PROGRAM_ID = Pubkey.from_string("6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P")

# --- Load Pump.fun IDL ---
try:
    # Ensure pump_fun_idl.json is in the same directory as this script
    # You might have named it 'pump-fun.json' if so, change the filename below
    with Path("pump_fun_idl.json").open() as f:
        raw_idl = f.read()
    pump_fun_idl = Idl.from_json(raw_idl)
    # We create a dummy Program instance just for its coder to decode logs
    pump_program_decoder = Program(pump_fun_idl, PUMPFUN_PROGRAM_ID)
    print("Pump.fun IDL loaded successfully for decoding.")
except FileNotFoundError:
    print("Error: pump_fun_idl.json not found. Please ensure it's in the same directory.")
    print("You can download it from: https://github.com/rckprtr/pumpdotfun-sdk/blob/main/src/IDL/pump-fun.json (click Raw and save)")
    print("Or use the pump-fun.json file you uploaded earlier and rename/use that filename.")
    exit()
except Exception as e:
    print(f"Error loading or parsing Pump.fun IDL: {e}")
    exit()


print(f"Connecting to Solana WebSocket at: {WSS_URL}")
print(f"Monitoring Pump.fun Program ID: {PUMPFUN_PROGRAM_ID}")

async def pump_fun_listener():
    """
    Listens for new token creations on Pump.fun via Solana WebSocket and decodes their data.
    """
    async with SolanaWsClient(WSS_URL) as ws:
        await ws.logs_subscribe(
            filter_by_mention=PUMPFUN_PROGRAM_ID,
            commitment="confirmed"
        )
        print("Subscribed to Pump.fun program logs. Waiting for new token creations...")

        async for msg in ws:
            if 'params' in msg and 'result' in msg['params'] and 'value' in msg['params']['result']:
                log_data = msg['params']['result'].get('value', {})
                signature = log_data.get('signature')
                logs = log_data.get('logs', [])

                is_new_token_creation = False
                program_data_log = None

                # First, identify the 'Instruction: Create' log and the subsequent 'Program data:' log
                for i, log_line in enumerate(logs):
                    if "Program log: Instruction: Create" in log_line:
                        is_new_token_creation = True
                        # Look for the 'Program data:' log, which typically follows an instruction log
                        if i + 1 < len(logs) and "Program data: " in logs[i+1]:
                            program_data_log = logs[i+1]
                        break # Found the create instruction, no need to check further logs for this tx

                if is_new_token_creation and program_data_log:
                    print(f"\n--- Detected Potential New Pump.fun Token Creation ---")
                    print(f"Transaction Signature: {signature}")
                    # print(f"Instruction Log: {log_line}") # Commented out for brevity, can uncomment if needed
                    print(f"Program Data Log: {program_data_log}")

                    try:
                        # Extract the base64 encoded data
                        base64_data = program_data_log.replace("Program data: ", "")
                        
                        # Decode the base64 data to bytes
                        decoded_bytes = base64.b64decode(base64_data)

                        # Use anchorpy's coder to decode the instruction
                        decoded_instruction = pump_program_decoder.coder.instruction.decode(decoded_bytes)
                        
                        if decoded_instruction and decoded_instruction.name == 'create':
                            print(f"Decoded Instruction Name: {decoded_instruction.name}")
                            print(f"Decoded Instruction Data (Args): {decoded_instruction.data}")
                            
                            # --- IMPORTANT: EXTRACTING MINT AND CREATOR ---
                            # This part requires careful mapping based on Pump.fun's IDL
                            # For the 'create' instruction in pump_fun_idl.json:
                            # 'mint' account is typically at index 0 in the transaction's accountKeys
                            # 'user' (creator) account is typically at index 4 in the transaction's accountKeys
                            # This mapping is derived from analyzing the IDL's 'accounts' array for the 'create' instruction.

                            account_keys = log_data.get('accountKeys', [])
                            
                            new_token_mint = None
                            creator_address = None

                            # Basic check to ensure indices exist before accessing
                            if len(account_keys) > 0: # Mint is often the first account
                                new_token_mint = Pubkey.from_string(account_keys[0])
                            if len(account_keys) > 4: # User/Creator is often the fifth account
                                creator_address = Pubkey.from_string(account_keys[4])


                            if new_token_mint and creator_address:
                                print(f"**Extracted New Token Mint:** {new_token_mint}")
                                print(f"**Extracted Creator Address:** {creator_address}")
                            else:
                                print("Could not reliably extract new token mint or creator address from accountKeys.")
                                print("Account Keys received:", [str(k) for k in account_keys])


                            # --- Next Steps Placeholder ---
                            # With new_token_mint and creator_address, you would proceed to:
                            # 1. Fetch more on-chain data for AI assessment (liquidity, supply, holders, etc.)
                            #    (e.g., using solana.rpc.api.Client for get_token_supply, get_token_account_balance, etc.)
                            # 2. Pass this data to your Gemini AI for potential classification.
                            # 3. If AI approves, monitor Pump progress (10-15%) and holder count (10-20) - this might require
                            #    more direct monitoring of the token's bonding curve state on Pump.fun.
                            # 4. If all criteria met, execute the trade.

                            print(f"Ready for AI assessment and trading logic for {new_token_mint}!")

                        else:
                            print(f"Decoded instruction is not 'create' or could not be decoded for signature: {signature}")

                    except Exception as e:
                        print(f"Error decoding instruction for signature {signature}: {e}")
                        # print(f"Raw data attempting to decode: {base64_data}") # Uncomment for debugging raw data

# Main entry point
if __name__ == "__main__":
    try:
        asyncio.run(pump_fun_listener())
    except KeyboardInterrupt:
        print("\nListener stopped by user.")
    except Exception as e:
        print(f"An error occurred: {e}")
