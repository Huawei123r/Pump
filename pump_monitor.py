# pump_monitor.py (Full Code - Latest Version with IDL Patching)

import asyncio
import json
import base64
from solana.rpc.websocket_api import connect
from solana.rpc.api import Client
from solders.pubkey import Pubkey
from solders.keypair import Keypair
from dotenv import load_dotenv
import os
from anchorpy import Program, Idl
from pathlib import Path

# Load environment variables from .env file
load_dotenv()

# --- Configuration ---
WSS_URL = os.getenv("SOLANA_WSS_URL")
HTTP_URL = os.getenv("SOLANA_HTTP_URL")
PRIVATE_KEY_B58 = os.getenv("SOLANA_PRIVATE_KEY")
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


# Initialize Solana RPC Client (for HTTP requests)
http_client = Client(HTTP_URL)

# Initialize your wallet keypair from the private key
try:
    wallet_keypair = Keypair.from_base58_string(PRIVATE_KEY_B58)
    print(f"Wallet Public Key: {wallet_keypair.pubkey()}")
except Exception as e:
    print(f"CRITICAL ERROR: Could not load Solana private key from .env: {e}")
    print("Please ensure SOLANA_PRIVATE_KEY is a valid Base58 encoded private key.")
    exit()


# Pump.fun program ID
PUMPFUN_PROGRAM_ID = Pubkey.from_string("6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P")


# --- Load and Patch Pump.fun IDL ---
try:
    with Path("pump-fun.json").open() as f:
        raw_idl_content = f.read()
    
    # Parse the raw JSON string into a Python dictionary
    idl_dict_to_patch = json.loads(raw_idl_content)

    # --- PATCHING LOGIC STARTS HERE ---
    # Iterate through all instructions and their accounts to add missing 'isMut' and 'isSigner'
    for instruction in idl_dict_to_patch.get('instructions', []):
        for account in instruction.get('accounts', []):
            # Check if 'isMut' or 'isSigner' are missing AND it's not a 'pda' or 'address' type that implies them
            # For PDA accounts or fixed address accounts, isMut and isSigner might be inferred or not needed if only for reference.
            # But the error implies anchorpy wants them explicitly for all 'IdlAccountItem' variants.
            # Safest to add them as False by default if they are missing, then let explicit definitions override.

            # We need to be careful not to overwrite existing correct values
            if 'isMut' not in account and 'writable' in account:
                account['isMut'] = account['writable'] # If 'writable' exists, use it
            elif 'isMut' not in account:
                account['isMut'] = False # Default to false if not specified

            if 'isSigner' not in account and 'signer' in account:
                account['isSigner'] = account['signer'] # If 'signer' exists, use it
            elif 'isSigner' not in account:
                account['isSigner'] = False # Default to false if not specified
            
            # Additional check for legacy IDL structures where 'writable'/'signer' might be absent too
            if 'writable' not in account and 'isMut' not in account:
                 account['isMut'] = False # Ensure isMut is set
            if 'signer' not in account and 'isSigner' not in account:
                 account['isSigner'] = False # Ensure isSigner is set

    # Some older IDLs also define 'accounts' at the top level outside of instructions.
    # While less common, this could also cause an issue if anchorpy tries to parse them
    # as IdlAccountItem. The error message 'line 33' points to instruction accounts though.
    # For safety, let's also patch global accounts if present:
    for global_account_def in idl_dict_to_patch.get('accounts', []):
        if 'isMut' not in global_account_def:
            global_account_def['isMut'] = False
        if 'isSigner' not in global_account_def:
            global_account_def['isSigner'] = False

    # Convert the patched dictionary back to an Idl object
    pump_fun_idl = Idl.from_json(json.dumps(idl_dict_to_patch)) # Convert dict back to JSON string
    pump_program_decoder = Program(pump_fun_idl, PUMPFUN_PROGRAM_ID)
    print("Pump.fun IDL loaded and patched successfully for decoding.")
except FileNotFoundError:
    print("CRITICAL ERROR: pump-fun.json not found.")
    print("Please ensure 'pump-fun.json' is in the same directory as this script.")
    print("Download from: https://raw.githubusercontent.com/rckprtr/pumpdotfun-sdk/main/src/IDL/pump-fun.json (click Raw and save)")
    exit()
except Exception as e:
    print(f"CRITICAL ERROR: Error loading, patching, or parsing Pump.fun IDL: {e}")
    # Print the problematic dictionary content for extreme debugging if needed
    # print(json.dumps(idl_dict_to_patch, indent=2))
    exit()


print(f"\nConnecting to Solana WebSocket at: {WSS_URL}")
print(f"Monitoring Pump.fun Program ID: {PUMPFUN_PROGRAM_ID}")

async def pump_fun_listener():
    """
    Listens for new token creations on Pump.fun via Solana WebSocket and decodes their data.
    """
    async with connect(WSS_URL) as ws:
        await ws.logs_subscribe(
            filter_by_mention=PUMPFUN_PROGRAM_ID,
            commitment="confirmed"
        )
        print("Subscribed to Pump.fun program logs. Waiting for new token creations on Mainnet...")

        first_response = await ws.recv()
        if isinstance(first_response, list) and len(first_response) > 0 and hasattr(first_response[0], 'result'):
            subscription_id = first_response[0].result
            print(f"Successfully subscribed with ID: {subscription_id}")
        else:
            print(f"Warning: Could not get subscription ID from first response: {first_response}")


        async for msg_list in ws:
            for msg in msg_list:
                if 'params' in msg and 'result' in msg['params'] and 'value' in msg['params']['result']:
                    log_data = msg['params']['result'].get('value', {})
                    signature = log_data.get('signature')
                    logs = log_data.get('logs', [])

                    is_new_token_creation = False
                    program_data_log_content = None

                    for i, log_line in enumerate(logs):
                        if "Program log: Instruction: Create" in log_line:
                            is_new_token_creation = True
                            if i + 1 < len(logs) and "Program data: " in logs[i+1]:
                                program_data_log_content = logs[i+1].replace("Program data: ", "")
                            break

                    if is_new_token_creation and program_data_log_content:
                        print(f"\n--- Detected Potential New Pump.fun Token Creation ---")
                        print(f"Transaction Signature: {signature}")
                        print(f"Raw Program Data Log Content: {program_data_log_content[:100]}...")

                        try:
                            decoded_bytes = base64.b64decode(program_data_log_content)
                            decoded_instruction = pump_program_decoder.coder.instruction.decode(decoded_bytes)
                            
                            if decoded_instruction and decoded_instruction.name == 'create':
                                print(f"Decoded Instruction Name: {decoded_instruction.name}")
                                print(f"Decoded Instruction Data (Args): {decoded_instruction.data}")
                                
                                account_keys_str = log_data.get('accountKeys', [])
                                
                                new_token_mint = None
                                creator_address = None

                                if len(account_keys_str) > 0:
                                    new_token_mint = Pubkey.from_string(account_keys_str[0])
                                if len(account_keys_str) > 4:
                                    creator_address = Pubkey.from_string(account_keys_str[4])

                                if new_token_mint and creator_address:
                                    print(f"**Extracted New Token Mint:** {new_token_mint}")
                                    print(f"**Extracted Creator Address:** {creator_address}")
                                    token_name = decoded_instruction.data.name
                                    token_symbol = decoded_instruction.data.symbol
                                    token_uri = decoded_instruction.data.uri
                                    print(f"Token Name: {token_name}, Symbol: {token_symbol}, URI: {token_uri}")
                                    
                                else:
                                    print("Warning: Could not reliably extract new token mint or creator address from accountKeys.")
                                    print(f"Account Keys received in log: {account_keys_str}")

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

