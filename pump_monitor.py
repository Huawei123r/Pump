# pump_monitor.py (Full Code - Latest Version with Syntax Error Fix)

import asyncio
import json
import base64
import websockets # Core library for WebSocket connections
import websockets.exceptions 
from solders.pubkey import Pubkey
from solders.keypair import Keypair
from dotenv import load_dotenv
import os
import borsh
import httpx # For general HTTP requests (e.g., to fetch token metadata from URI, or interact with RPC via HTTP)
import google.generativeai as genai # Import Google Gemini AI library

from pathlib import Path

# --- Configuration ---
load_dotenv()

WSS_URL = os.getenv("SOLANA_WSS_URL")
HTTP_URL = os.getenv("SOLANA_HTTP_URL")
PRIVATE_KEY_B58 = os.getenv("SOLANA_PRIVATE_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
BUY_SOL_AMOUNT = float(os.getenv("BUY_SOL_AMOUNT", "0.001")) # Default to 0.001 SOL if not set

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
if BUY_SOL_AMOUNT <= 0:
    print("CRITICAL ERROR: BUY_SOL_AMOUNT must be a positive number. Exiting.")
    exit()


# Configure Google Gemini API
genai.configure(api_key=GEMINI_API_KEY)
# Initialize the generative model
gemini_model = genai.GenerativeModel('gemini-pro') # Using gemini-pro for text tasks

# Initialize an asynchronous HTTP client for fetching external data
http_client = httpx.AsyncClient()


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

async def get_ai_assessment(token_name, token_symbol, token_uri, new_token_mint):
    """
    Calls Gemini AI to assess the token's legitimacy/potential.
    """
    prompt = (
        f"Analyze this newly created Solana meme token and provide a brief assessment "
        f"of its potential, legitimacy, or any red flags based on the provided information. "
        f"Focus on the name, symbol, and URI content. "
        f"Token Name: '{token_name}', Symbol: '{token_symbol}', Mint Address: '{new_token_mint}'.\n"
        f"URI: '{token_uri}' (You may attempt to fetch and analyze content from this URI if it's a valid URL, "
        f"but do not make external network calls if not possible or if it's not a standard HTTP/S URI).\n"
        f"Provide your assessment as a short, concise paragraph (max 100 words), and then state 'Assessment: [Positive/Neutral/Negative]'."
    )
    
    uri_content = "URI content not fetched or not applicable."
    if token_uri.startswith("http://") or token_uri.startswith("https://"):
        try:
            response = await http_client.get(token_uri, timeout=5) # Use the global async client
            response.raise_for_status()
            uri_content = response.text[:500]
            prompt += f"\n\nURI Content (first 500 chars): {uri_content}"
        except Exception as e:
            uri_content = f"Failed to fetch URI content: {e}"
            prompt += f"\n\nNote: Failed to fetch URI content for AI analysis: {uri_content}"
    elif token_uri.startswith("ipfs://"):
        prompt += f"\n\nNote: IPFS URI detected. Content not automatically fetched for AI analysis."

    try:
        print(f"Sending token data to Gemini AI for assessment...")
        ai_response = await gemini_model.generate_content_async(prompt)
        assessment_text = ai_response.text
        print(f"AI Assessment Received:\n{assessment_text}")
        return assessment_text
    except Exception as e:
        print(f"Error getting AI assessment: {e}")
        return f"AI assessment failed: {e}"

# --- Placeholder for future buy logic ---
async def execute_buy_trade(token_mint: Pubkey, sol_amount: float, wallet_keypair: Keypair):
    """
    Placeholder function for executing a buy trade on Pump.fun.
    THIS FUNCTION NEEDS FULL IMPLEMENTATION.
    """
    print(f"ACTION: Attempting to buy {sol_amount} SOL worth of {token_mint}...")
    print("WARNING: Actual trading logic is not yet implemented in this bot!")
    # Example steps (will require more code):
    # 1. Fetch current bonding curve state (virtual_sol_reserves, virtual_token_reserves) using RPC.
    # 2. Calculate token amount to receive and estimated slippage.
    # 3. Build a Solana transaction with the Pump.fun 'buy' instruction.
    #    (This involves: program ID, buyer's token account, bonding curve account, global account, etc.)
    # 4. Sign the transaction with wallet_keypair.
    # 5. Send the transaction via HTTP_URL RPC.
    # 6. Monitor transaction confirmation.
    # For now, we'll just simulate.
    await asyncio.sleep(2) # Simulate network delay
    print(f"SIMULATION: Would have bought {sol_amount} SOL worth of {token_mint}. (Trade not executed)")
    return "SIMULATED_TRADE_SUCCESS"


print(f"Connecting to Solana WebSocket at: {WSS_URL}")
print(f"Monitoring Pump.fun Program ID: {PUMPFUN_PROGRAM_ID}")

async def pump_fun_listener():
    """
    Listens for logs on Solana Mainnet by sending a raw JSON-RPC WebSocket subscribe request.
    Integrates Gemini AI for token analysis and includes a placeholder for buy actions.
    """
    # Consolidate all connection-related errors into one try-except block
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

            # Handle initial response
            first_response_raw = await ws.recv() # Get raw string
            print(f"Received first response (raw): {first_response_raw}")

            parsed_first_response = json.loads(first_response_raw)
            if 'result' in parsed_first_response and 'id' in parsed_first_response:
                subscription_id = parsed_first_response['result']
                print(f"Successfully subscribed with ID: {subscription_id}")
            elif 'error' in parsed_first_response:
                print(f"ERROR: RPC returned an error in first response: {parsed_first_response['error']}")
                # Re-raise the error so the outer `try-except` in __main__ catches it
                raise Exception(f"RPC Error during subscription: {parsed_first_response['error']}")
            else:
                print(f"Warning: Unexpected first response structure: {parsed_first_response}")
                raise Exception(f"Unexpected first response: {parsed_first_response}")

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
                                
                                # --- Call Gemini AI for assessment ---
                                ai_assessment = await get_ai_assessment(
                                    token_name, 
                                    token_symbol, 
                                    token_uri, 
                                    new_token_mint
                                )
                                print(f"\nAI Assessment Complete for {token_symbol}: {ai_assessment.split('Assessment:')[-1].strip()}")

                                # --- Your trading decision logic would go here ---
                                # This is where you'd decide whether to buy based on AI assessment
                                if "Positive" in ai_assessment: # Example condition
                                    print(f"AI assessment for {token_symbol} is Positive. Initiating simulated buy...")
                                    await execute_buy_trade(new_token_mint, BUY_SOL_AMOUNT, wallet_keypair)
                                else:
                                    print(f"AI assessment for {token_symbol} is not Positive. Skipping buy.")

                            else:
                                print("Warning: Could not reliably extract new token mint or creator address.")
                                print(f"Account Keys received in log: {account_keys_str}")

                            print(f"Proceeding to AI assessment and potential trading decision for {new_token_mint}!")

                        except ValueError as ve:
                            print(f"Error during manual Borsh decoding: {ve}")
                            print(f"Problematic base64 data: {program_data_log_content}")
                        except Exception as e:
                            print(f"An unexpected error occurred during processing for signature {signature}: {e}")
                            print(f"Problematic base64 data: {program_data_log_content}")
    except websockets.exceptions.ConnectionClosedOK as e:
        print(f"ERROR: WebSocket connection closed gracefully (OK): {e}")
        print(f"Code: {e.code}, Reason: {e.reason}")
    except websockets.exceptions.ConnectionClosedError as e:
        print(f"CRITICAL ERROR: WebSocket connection closed abnormally: {e}")
        print(f"Code: {e.code}, Reason: {e.reason}")
    except json.JSONDecodeError as e:
        print(f"CRITICAL ERROR: Could not decode WebSocket message as JSON: {e}")
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

