module Node.Crypto.Decipher
  ( Decipher
  , fromHex
  , fromBase64
  , createDecipher
  , decipher'
  , update
  , final
  ) where

import Prelude
import Effect (Effect)
import Node.Encoding (Encoding(UTF8, Hex, Base64))
import Node.Buffer (Buffer, fromString, toString, concat)
import Node.Crypto.Cipher (Algorithm, Mode, Password, algoName)

foreign import data Decipher :: Type

fromHex
  :: Algorithm
  -> Password
  -> String
  -> Effect String
fromHex alg password str = decipher alg password str Hex

fromBase64
  :: Algorithm
  -> Password
  -> String
  -> Effect String
fromBase64 alg password str = decipher alg password str Base64

decipher
  :: Algorithm
  -> Password
  -> String
  -> Encoding
  -> Effect String
decipher alg password str enc = do
  buf <- fromString str enc
  dec <- createDecipher alg password
  rbuf1 <- update dec buf
  rbuf2 <- final dec
  rbuf <- concat [ rbuf1, rbuf2 ]
  toString UTF8 rbuf

decipher'
  :: Algorithm
  -> Mode
  -> Buffer
  -> Buffer
  -> Buffer
  -> Encoding
  -> Effect Buffer
decipher' alg padding password iv buf enc = do
  dec <- createDecipher' alg padding password iv
  rbuf1 <- update dec buf
  rbuf2 <- final dec
  rbuf <- concat [ rbuf1, rbuf2 ]
  pure rbuf

createDecipher :: Algorithm -> Password -> Effect Decipher
createDecipher alg password = _createDecipher (show alg) password

createDecipher' :: Algorithm -> Mode -> Buffer -> Buffer -> Effect Decipher
createDecipher' alg mode password iv = _createDecipherIV ((algoName alg) <> (show mode)) password iv

foreign import _createDecipher
  :: String
  -> String
  -> Effect Decipher

foreign import _createDecipherIV
  :: String
  -> Buffer
  -> Buffer
  -> Effect Decipher

foreign import update :: Decipher -> Buffer -> Effect Buffer

foreign import final :: Decipher -> Effect Buffer
