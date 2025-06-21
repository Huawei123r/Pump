# pump_monitor.py (Full Code - Latest Version with IDL Debugging)

import asyncio
import json
import base64
# Corrected import for WebSocket connection for solana-py >= 0.29.x
from solana.rpc.websocket_api import connect
from solana.rpc.api import Client # For HTTP requests (e.g., getting balance, sending transactions)
from solders.pubkey import Pubkey
from solders.keypair import Keypair # For handling your private key
from dotenv import load_dotenv
import os
from anchorpy import Program, Idl
from pathlib import Path

# Load environment variables from .env file
load_dotenv()

# --- Configuration ---
# Now load the WSS_URL from your .env file
WSS_URL = os.getenv("SOLANA_WSS_URL")
# Also load HTTP_URL for standard requests (will be used later for sending transactions)
HTTP_URL = os.getenv("SOLANA_HTTP_URL")
# Load your private key (WARNING: INSECURE FOR REAL FUNDS, USE BURNER WALLET ONLY)
PRIVATE_KEY_B58 = os.getenv("SOLANA_PRIVATE_KEY")
# Load Gemini API Key
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

# --- Basic Validation of .env variables ---
if not WSS_URL:
    print("CRITICAL ERROR: SOLANA_WSS_URL not found in .env. Exiting.")
    exit()
if not HTTP_URL:
    print("CRITICAL ERROR: SOLANA_HTTP_URL not found in .env. Exiting.")
    exit()
if not PRIVATE_KEY_B58:
    print("CRITICAL ERROR: SOLANA_PRIVATE_KEY not found in .env. Exiting.")
    exit()
if not GEMINI_API_KEY:
    print("CRITICAL ERROR: GEMINI_API_KEY not found in .env. Exiting.")
    exit()


# Initialize Solana RPC Client (for HTTP requests like getting account info)
http_client = Client(HTTP_URL)

# Initialize your wallet keypair from the private key
try:
    # Keypair.from_base58_string expects a Base58 encoded string
    wallet_keypair = Keypair.from_base58_string(PRIVATE_KEY_B58)
    print(f"Wallet Public Key: {wallet_keypair.pubkey()}")
except Exception as e:
    print(f"CRITICAL ERROR: Could not load Solana private key from .env: {e}")
    print("Please ensure SOLANA_PRIVATE_KEY is a valid Base58 encoded private key.")
    exit()


# Pump.fun program ID (remains constant)
PUMPFUN_PROGRAM_ID = Pubkey.from_string("6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P")


# --- Load Pump.fun IDL ---
try:
    # *** MODIFICATION HERE: Using "pump-fun.json" as per your file system ***
    with Path("pump-fun.json").open() as f:
        raw_idl = f.read()

    # --- TEMPORARY DEBUGGING CODE ---
    # Parse the raw JSON string to a Python dict to inspect it
    temp_idl_dict = json.loads(raw_idl)
    
    # Try to extract the 'create' instruction's accounts
    create_instruction_accounts = None
    for instr in temp_idl_dict.get('instructions', []):
        if instr.get('name') == 'create':
            create_instruction_accounts = instr.get('accounts')
            break
            
    if create_instruction_accounts:
        print("\n--- DEBUG: 'create' instruction accounts from raw_idl ---")
        # Print the first few accounts from the 'create' instruction
        for i, account in enumerate(create_instruction_accounts[:5]): # Print first 5 accounts
            print(f"Account {i}: {json.dumps(account, indent=2)}")
        print("--- END DEBUG ---\n")
    else:
        print("\n--- DEBUG: 'create' instruction not found in IDL or no accounts ---")
    # --- END TEMPORARY DEBUGGING CODE ---


    pump_fun_idl = Idl.from_json(raw_idl) # This line will still cause the error if the IDL is bad
    print("Pump.fun IDL loaded successfully for decoding.")
except FileNotFoundError:
    print("CRITICAL ERROR: pump-fun.json not found.")
    print("Please ensure 'pump-fun.json' is in the same directory as this script.")
    print("You downloaded it from: https://raw.githubusercontent.com/rckprtr/pumpdotfun-sdk/main/src/IDL/pump-fun.json (click Raw and save)")
    exit()
except Exception as e:
    print(f"CRITICAL ERROR: Error loading or parsing Pump.fun IDL: {e}")
    exit()


print(f"\nConnecting to Solana WebSocket at: {WSS_URL}")
print(f"Monitoring Pump.fun Program ID: {PUMPFUN_PROGRAM_ID}")

async def pump_fun_listener():
    """
    Listens for new token creations on Pump.fun via Solana WebSocket and decodes their data.
    """
    # Use the 'connect' function from solana.rpc.websocket_api
    async with connect(WSS_URL) as ws:
        # First, subscribe to the logs.
        # The logs_subscribe method returns a subscription ID in the first response.
        # We need to receive that response to get the ID.
        await ws.logs_subscribe(
            filter_by_mention=PUMPFUN_PROGRAM_ID,
            commitment="confirmed" # 'confirmed' commitment balances speed with reliability
        )
        print("Subscribed to Pump.fun program logs. Waiting for new token creations on Mainnet...")

        # The first message received after subscribing contains the subscription ID
        # This is part of the WebSocket handshake for subscriptions
        first_response = await ws.recv()
        # Verify the structure to safely extract the subscription ID
        if isinstance(first_response, list) and len(first_response) > 0 and hasattr(first_response[0], 'result'):
            subscription_id = first_response[0].result
            print(f"Successfully subscribed with ID: {subscription_id}")
        else:
            print(f"Warning: Could not get subscription ID from first response: {first_response}")


        # Now, continuously receive messages from the WebSocket
        async for msg_list in ws: # ws yields a list of messages
            # Each message in msg_list could be a notification or a keep-alive
            for msg in msg_list:
                # Check if it's a log notification with relevant data
                if 'params' in msg and 'result' in msg['params'] and 'value' in msg['params']['result']:
                    log_data = msg['params']['result'].get('value', {})
                    signature = log_data.get('signature')
                    logs = log_data.get('logs', [])

                    is_new_token_creation = False
                    program_data_log_content = None # Store the content for decoding

                    # Iterate through logs to find the "Instruction: Create" and subsequent "Program data:"
                    for i, log_line in enumerate(logs):
                        if "Program log: Instruction: Create" in log_line:
                            is_new_token_creation = True
                            # The 'Program data:' log is usually right after the 'Instruction: Create'
                            if i + 1 < len(logs) and "Program data: " in logs[i+1]:
                                program_data_log_content = logs[i+1].replace("Program data: ", "")
                            break # Found the create instruction, no need to check further logs for this transaction

                    if is_new_token_creation and program_data_log_content:
                        print(f"\n--- Detected Potential New Pump.fun Token Creation ---")
                        print(f"Transaction Signature: {signature}")
                        # print(f"Raw Instruction Log: {log_line}") # Can uncomment for debugging
                        print(f"Raw Program Data Log Content: {program_data_log_content[:100]}...") # Print first 100 chars

                        try:
                            # Decode the base64 data to bytes
                            decoded_bytes = base64.b64decode(program_data_log_content)

                            # Use anchorpy's instruction coder to decode the instruction data
                            decoded_instruction = pump_program_decoder.coder.instruction.decode(decoded_bytes)
                            
                            if decoded_instruction and decoded_instruction.name == 'create':
                                print(f"Decoded Instruction Name: {decoded_instruction.name}")
                                # The 'data' attribute here refers to the instruction arguments
                                print(f"Decoded Instruction Data (Args): {decoded_instruction.data}")
                                
                                # --- IMPORTANT: EXTRACTING MINT AND CREATOR ADDRESSES ---
                                # The `accountKeys` array in the `log_data` contains the public keys
                                # involved in the transaction. We need to map these to the 'mint'
                                # and 'user' (creator) accounts as defined in the Pump.fun IDL
                                # for the 'create' instruction.
                                # Based on the pump-fun.json IDL 'create' instruction's `accounts` array:
                                # The 'mint' account is usually the first Pubkey in the `accountKeys` list (index 0).
                                # The 'user' (creator) account is usually the fifth Pubkey (index 4).

                                account_keys_str = log_data.get('accountKeys', []) # List of base58 encoded pubkeys
                                
                                new_token_mint = None
                                creator_address = None

                                # Safely extract based on expected indices from IDL
                                if len(account_keys_str) > 0:
                                    new_token_mint = Pubkey.from_string(account_keys_str[0])
                                if len(account_keys_str) > 4:
                                    creator_address = Pubkey.from_string(account_keys_str[4])

                                if new_token_mint and creator_address:
                                    print(f"**Extracted New Token Mint:** {new_token_mint}")
                                    print(f"**Extracted Creator Address:** {creator_address}")

                                    # You can also get other data from decoded_instruction.data, e.g.:
                                    token_name = decoded_instruction.data.name
                                    token_symbol = decoded_instruction.data.symbol
                                    token_uri = decoded_instruction.data.uri
                                    print(f"Token Name: {token_name}, Symbol: {token_symbol}, URI: {token_uri}")
                                    
                                else:
                                    print("Warning: Could not reliably extract new token mint or creator address from accountKeys.")
                                    print(f"Account Keys received in log: {account_keys_str}")

                                # --- NEXT MAJOR STEPS after successful token detection and data extraction ---
                                # 1. Fetch more on-chain data using http_client (e.g., current liquidity, total supply, current holder count)
                                #    (e.g., `http_client.get_token_supply(new_token_mint)`, `http_client.get_token_largest_accounts(new_token_mint)`)
                                # 2. Pass this collected data along with token name/symbol to your Gemini AI for classification.
                                # 3. Implement trading logic: If AI approves, and other criteria (like bonding curve progress,
                                #    initial holder count, etc. which need to be fetched/monitored) are met, execute a buy trade.
                                #    This will involve using your `wallet_keypair` and `http_client` to send a transaction.
                                # 4. Implement selling logic based on your basic strategy (e.g., fixed profit/loss).

                                print(f"Proceeding to AI assessment and trading decision for {new_token_mint}!")

                            else:
                                print(f"Instruction decoded, but it's not the expected 'create' instruction or data is malformed for signature: {signature}")

                        except Exception as e:
                            print(f"Error during decoding or data extraction for signature {signature}: {e}")
                            print(f"Problematic base64 data: {program_data_log_content}")

# Main entry point for the asyncio event loop
if __name__ == "__main__":
    print("Starting Pump.fun monitor...")
    try:
        asyncio.run(pump_fun_listener())
    except KeyboardInterrupt:
        print("\nListener stopped by user (KeyboardInterrupt).")
    except Exception as e:
        print(f"An unexpected error occurred in the main loop: {e}")

