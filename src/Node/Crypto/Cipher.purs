module Node.Crypto.Cipher
  ( Cipher
  , Algorithm(..)
  , Mode(..)
  , Password
  , hex
  , base64
  , cipher
  , cipher'
  , createCipher
  , createcipher'
  , update
  , final
  , makeBufferPassword
  , algoName
  ) where

import Prelude

import Effect (Effect)
import Node.Buffer (Buffer, fromString, toString, concat)
import Node.Buffer as Buffer
import Node.Encoding (Encoding(UTF8, Hex, Base64))

foreign import data Cipher :: Type

data Algorithm
  = AES128
  | AES192
  | AES256

type Password
  = String

instance showAlgorithm :: Show Algorithm where
  show AES128 = "AES128"
  show AES192 = "AES192"
  show AES256 = "AES256"

-- Available modes for AES ciphers.
data Mode
  = ModeDefault
  | CBC
  | CFB
  | CFB1
  | CFB8
  | CTR
  | ECB

instance showMode :: Show Mode where
  show ModeDefault = "-cbc"
  show CBC = "-cbc"
  show CFB = "-cfb"
  show CFB1 = "-cfb1"
  show CFB8 = "-cfb8"
  show CTR = "-ctr"
  show ECB = "-ecb"

hex ::
  Algorithm ->
  Password ->
  String ->
  Effect String
hex alg password str = cipher alg password str Hex

base64 ::
  Algorithm ->
  Password ->
  String ->
  Effect String
base64 alg password str = cipher alg password str Base64

cipher ::
  Algorithm ->
  Password ->
  String ->
  Encoding ->
  Effect String
cipher alg password str enc = do
  buf <- fromString str UTF8
  cip <- createCipher alg password
  rbuf1 <- update cip buf
  rbuf2 <- final cip
  rbuf <- concat [ rbuf1, rbuf2 ]
  toString enc rbuf

hex' ::
  Algorithm ->
  Mode ->
  Buffer ->
  Buffer ->
  String ->
  Effect Buffer
hex' alg mode password iv str = cipher' alg mode password iv str Hex

base64' ::
  Algorithm ->
  Mode ->
  Buffer ->
  Buffer ->
  String ->
  Effect Buffer
base64' alg mode password iv str = cipher' alg mode password iv str Base64

cipher' ::
  Algorithm ->
  Mode ->
  Buffer ->
  Buffer ->
  String ->
  Encoding ->
  Effect Buffer
cipher' alg mode password iv str enc = do
  buf <- fromString str UTF8
  cip <- createcipher' alg mode password iv
  rbuf1 <- update cip buf
  rbuf2 <- final cip
  rbuf <- concat [ rbuf1, rbuf2 ]
  -- Buffer.toString enc rbuf
  pure rbuf

-- | AES algorithms want passwords padded (or truncated) to a specific length.
padBufferPassword :: Int -> Buffer -> Effect Buffer
padBufferPassword len buf = do
  byteCount <- Buffer.size buf
  if byteCount < len then do
    padding <- Buffer.create (len - byteCount)
    padded <- Buffer.concat [ buf, padding ]
    pure padded
  else
    pure $ Buffer.slice 0 len buf

-- | Pad password buffer to correct size for an AES algorithm.
makeBufferPassword :: Algorithm -> Buffer -> Effect Buffer
makeBufferPassword alg buf =
  case alg of
    AES128 -> padBufferPassword 16 buf
    AES192 -> padBufferPassword 24 buf
    AES256 -> padBufferPassword 32 buf

createCipher :: Algorithm -> Password -> Effect Cipher
createCipher alg password = _createCipher (show alg) password

-- Node.Crypto is inconsistent in naming the algorithms.
-- createCipher wants no dash, createCiperIV requires it
algoName :: Algorithm -> String
algoName alg = case alg of
  AES128 -> "aes-128"
  AES192 -> "aes-192"
  AES256 -> "aes-256"

createcipher' :: Algorithm -> Mode -> Buffer -> Buffer -> Effect Cipher
createcipher' alg mode password iv = _createCipherIV (algoName alg <> (show mode)) password iv

foreign import _createCipher ::
  String ->
  String ->
  Effect Cipher

foreign import _createCipherIV ::
  String ->
  Buffer ->
  Buffer ->
  Effect Cipher

foreign import update :: Cipher -> Buffer -> Effect Buffer

foreign import final :: Cipher -> Effect Buffer
