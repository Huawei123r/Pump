# pump_monitor.py (Full Code - Latest Version, Switching to Mainnet)

import asyncio
import json
import base64
import websockets # Import the raw websockets library
import websockets.exceptions 
from solders.pubkey import Pubkey
from solders.keypair import Keypair
from dotenv import load_dotenv
import os
import borsh
# We will re-add solana.rpc.api.Client for HTTP requests later as needed.
# For now, stick to raw websockets for the listener.

from pathlib import Path

# --- Configuration ---
load_dotenv()

# --- Revert to Mainnet URLs from .env ---
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


# We will need an HTTP client for fetching balances, etc. Let's re-add httpx for general HTTP requests
# Since we removed solana.rpc.api.Client, we need a generic one.
import httpx # NEW: Import httpx for general HTTP requests

# Initialize a generic HTTP client
http_client = httpx.Client() # Use httpx for regular HTTP requests


try:
    wallet_keypair = Keypair.from_base58_string(PRIVATE_KEY_B58)
    print(f"Wallet Public Key: {wallet_keypair.pubkey()}")
except Exception as e:
    print(f"CRITICAL ERROR: Could not load Solana private key from .env: {e}")
    print("Please ensure SOLANA_PRIVATE_KEY is a valid Base58 encoded private key.")
    exit()


PUMPFUN_PROGRAM_ID = Pubkey.from_string("6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P")
PUMPFUN_PROGRAM_ID_STR = str(PUMPFUN_PROGRAM_ID) 

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
    """
    Listens for logs on Solana Mainnet by sending a raw JSON-RPC WebSocket subscribe request.
    """
    try:
        async with websockets.connect(WSS_URL) as ws:
            subscribe_request = {
                "jsonrpc": "2.0",
                "id": 1, 
                "method": "logsSubscribe",
                "params": [
                    {"mentions": [PUMPFUN_PROGRAM_ID_STR]}, # Filter by Pump.fun program ID as a string
                    {"commitment": "confirmed"}
                ]
            }
            
            await ws.send(json.dumps(subscribe_request))
            print(f"Sent subscription request: {json.dumps(subscribe_request)}")

            try:
                print(f"Awaiting first response (expecting subscription ID or error from RPC)...")
                first_response_raw = await ws.recv() # Get raw string
                print(f"Received first response (raw): {first_response_raw}")

                parsed_first_response = json.loads(first_response_raw)
                if 'result' in parsed_first_response and 'id' in parsed_first_response:
                    subscription_id = parsed_first_response['result']
                    print(f"Successfully subscribed with ID: {subscription_id}")
                elif 'error' in parsed_first_response:
                    print(f"ERROR: RPC returned an error in first response: {parsed_first_response['error']}")
                    raise Exception(f"RPC Error: {parsed_first_response['error']}")
                else:
                    print(f"Warning: Unexpected first response structure: {parsed_first_response}")
                    raise Exception(f"Unexpected first response: {parsed_first_response}")

            except websockets.exceptions.ConnectionClosedOK as e:
                print(f"ERROR: WebSocket connection closed gracefully (OK): {e}")
                print(f"Code: {e.code}, Reason: {e.reason}")
                return
            except websockets.exceptions.ConnectionClosedError as e:
                print(f"CRITICAL ERROR: WebSocket connection closed abnormally: {e}")
                print(f"Code: {e.code}, Reason: {e.reason}")
                return
            except json.JSONDecodeError as e:
                print(f"CRITICAL ERROR: Could not decode first response as JSON: {e}")
                print(f"Problematic raw response: {first_response_raw}")
                return
            except Exception as e:
                print(f"CRITICAL ERROR: An unexpected error occurred during initial subscription handshake: {e}")
                return


            print("Waiting for new token creations (filtering in Python)...")

            async for msg_str in ws:
                try:
                    msg = json.loads(msg_str)
                except json.JSONDecodeError:
                    continue

                if 'params' in msg and 'result' in msg['params'] and 'value' in msg['params']['result']:
                    log_data = msg['params']['result'].get('value', {})
                    signature = log_data.get('signature')
                    logs = log_data.get('logs', [])
                    
                    account_keys_str = log_data.get('accountKeys', [])
                    if PUMPFUN_PROGRAM_ID_STR not in account_keys_str:
                        continue


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
    except Exception as e:
        print(f"CRITICAL ERROR: An unhandled exception occurred in the pump_fun_listener: {e}")


# Main entry point for the asyncio event loop
if __name__ == "__main__":
    print("Starting Pump.fun monitor...")
    try:
        asyncio.run(pump_fun_listener())
    except KeyboardInterrupt:
        print("\nListener stopped by user (KeyboardInterrupt).")
    except Exception as e:
        print(f"An unexpected error occurred in the main loop: {e}")

