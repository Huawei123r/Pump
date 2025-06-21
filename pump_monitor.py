# pump_monitor.py (Full Code - Latest Version with RpcLogsFilter Import Final Fix)

import asyncio
import json
import base64
from solana.rpc.websocket_api import connect
from solana.rpc.api import Client
from solders.pubkey import Pubkey
from solders.keypair import Keypair
from dotenv import load_dotenv
import os
import borsh
# CORRECTED: Import RpcLogsFilter from its correct location in solders
from solders.rpc.config import RpcLogsFilter # This is the standard path in recent solders versions
from pathlib import Path

# --- Configuration ---
load_dotenv()

WSS_URL = os.getenv("SOLANA_WSS_URL")
HTTP_URL = os.getenv("SOLANA_HTTP_URL")
PRIVATE_KEY_B58 = os.getenv("SOLANA_PRIVATE_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

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


http_client = Client(HTTP_URL)

try:
    wallet_keypair = Keypair.from_base58_string(PRIVATE_KEY_B58)
    print(f"Wallet Public Key: {wallet_keypair.pubkey()}")
except Exception as e:
    print(f"CRITICAL ERROR: Could not load Solana private key from .env: {e}")
    print("Please ensure SOLANA_PRIVATE_KEY is a valid Base58 encoded private key.")
    exit()


PUMPFUN_PROGRAM_ID = Pubkey.from_string("6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P")

CREATE_INSTRUCTION_DISCRIMINATOR = bytes([24, 30, 200, 40, 5, 28, 7, 119])

def decode_create_instruction_data(data_bytes: bytes):
    if not data_bytes.startswith(CREATE_INSTRUCTION_DISCRIMINATOR):
        raise ValueError("Data does not start with 'create' instruction discriminator.")

    payload_bytes = data_bytes[8:]
    reader = borsh.Borsh(payload_bytes)

    try:
        name_len = reader.read_u32()
        name = reader.read_bytes(name_len).decode('utf-8')

        symbol_len = reader.read_u32()
        symbol = reader.read_bytes(symbol_len).decode('utf-8')

        uri_len = reader.read_u32()
        uri = reader.read_bytes(uri_len).decode('utf-8')

        creator_bytes = reader.read_bytes(32)
        creator = Pubkey.from_bytes(creator_bytes)

        return {
            "name": name,
            "symbol": symbol,
            "uri": uri,
            "creator": creator
        }
    except Exception as e:
        print(f"Error during manual Borsh deserialization: {e}")
        raise


print(f"Connecting to Solana WebSocket at: {WSS_URL}")
print(f"Monitoring Pump.fun Program ID: {PUMPFUN_PROGRAM_ID}")

async def pump_fun_listener():
    async with connect(WSS_URL) as ws:
        # --- NEW: Corrected logs_subscribe syntax with RpcLogsFilter from solders.rpc.config ---
        await ws.logs_subscribe(
            filter_=RpcLogsFilter.Mentions([str(PUMPFUN_PROGRAM_ID)]), # Use RpcLogsFilter.Mentions
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
                            decoded_instruction_args = decode_create_instruction_data(decoded_bytes)
                            
                            print(f"Decoded Instruction Data (Args): {decoded_instruction_args}")
                            
                            creator_address_from_args = decoded_instruction_args.get("creator")

                            account_keys_str = log_data.get('accountKeys', [])
                            new_token_mint = None
                            if len(account_keys_str) > 0:
                                new_token_mint = Pubkey.from_string(account_keys_str[0])

                            if new_token_mint and creator_address_from_args:
                                print(f"**Extracted New Token Mint:** {new_token_mint}")
                                print(f"**Extracted Creator Address (from args):** {creator_address_from_args}")
                                token_name = decoded_instruction_args.get("name", "N/A")
                                token_symbol = decoded_instruction_args.get("symbol", "N/A")
                                token_uri = decoded_instruction_args.get("uri", "N/A")
                                print(f"Token Name: {token_name}, Symbol: {token_symbol}, URI: {token_uri}")
                                
                            else:
                                print("Warning: Could not reliably extract new token mint or creator address.")
                                print(f"Account Keys received in log: {account_keys_str}")

                            print(f"Proceeding to AI assessment and trading decision for {new_token_mint}!")

                        except ValueError as ve:
                            print(f"Error during manual Borsh decoding: {ve}")
                            print(f"Problematic base64 data: {program_data_log_content}")
                        except Exception as e:
                            print(f"An unexpected error occurred during processing for signature {signature}: {e}")
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

