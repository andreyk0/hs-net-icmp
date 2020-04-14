{-# LANGUAGE RecordWildCards     #-}
{-# LANGUAGE ScopedTypeVariables #-}

{-- https://en.wikipedia.org/wiki/Ping_(networking_utility)
 -  IPV4 ICMP models, encoding, decoding.
 --}
module Net.ICMP.V4.Internal where


import           Data.Binary
import           Data.Binary.Get
import           Data.Bits
import           Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString.Lazy as LB


data DestinationUnreachableCode = DestinationNetworkUnreachable
    | DestinationHostUnreachable
    | DestinationProtocolUnreachable
    | DestinationPortUnreachable
    | FragmentationRequired
    | SourceRouteFailed
    | DestinationNetworkUnknown
    | DestinationHostUnknown
    | SourceHostIsolated
    | NetworkAdministrativelyProhibited
    | HostAdministrativelyProhibited
    | NetworkUnreachableForToS
    | HostUnreachableForToS
    | CommunicationAdministrativelyProhibited
    | HostPrecedenceViolation
    | PrecedenceCutoffInEffect
    deriving (Eq, Show, Bounded, Enum)


data RedirectCode = RedirectNetwork
    | RedirectHost
    | RedirectToSAndNetwork
    | RedirectToSAndHost
    deriving (Eq, Show, Bounded, Enum)



data TimeExceededCode = TTLExpiredInTransit
    | FragmentReassemblyTimeExceeded
    deriving (Eq, Show, Bounded, Enum)


data ParameterProblemCode = PointerIndicatesTheError
    | MissingARequiredOption
    | BadLength
    deriving (Eq, Show, Bounded, Enum)


-- https://tools.ietf.org/html/rfc792
data ICMPMessageType = EchoReply
    | DestinationUnreachable !DestinationUnreachableCode
    | Redirect !RedirectCode
    | EchoRequest
    | RouterAdvertisement
    | RouterSolicitation
    | TimeExceeded !TimeExceededCode
    | ParameterProblem !ParameterProblemCode
    | Timestamp
    | TimestampReply
    | OtherMessage !Word8 !Word8
    deriving (Eq, Show)


encodeIcmpMessageType :: ICMPMessageType -> (Word8, Word8)
encodeIcmpMessageType m = case m of
  EchoReply                  -> (0,  0)
  DestinationUnreachable duc -> (3,  mcode duc)
  Redirect rc                -> (5,  mcode rc)
  EchoRequest                -> (8,  0)
  RouterAdvertisement        -> (9,  0)
  RouterSolicitation         -> (10, 0)
  TimeExceeded tec           -> (11, mcode tec)
  ParameterProblem ppc       -> (12, mcode ppc)
  Timestamp                  -> (13, 0)
  TimestampReply             -> (14, 0)
  OtherMessage t c           -> (t,  c)
  where mcode :: (Enum a) => a -> Word8
        mcode = fromIntegral . fromEnum


decodeIcmpMessageType :: Word8 -> Word8 -> Either String ICMPMessageType
decodeIcmpMessageType 0  0   = Right EchoReply
decodeIcmpMessageType 3  duc = fmap DestinationUnreachable (word8ToEnumErr "DestinationUnreachableCode" duc)
decodeIcmpMessageType 5  rc  = fmap Redirect (word8ToEnumErr "RedirectCode" rc)
decodeIcmpMessageType 8  0   = return EchoRequest
decodeIcmpMessageType 9  0   = return RouterAdvertisement
decodeIcmpMessageType 10 0   = return RouterSolicitation
decodeIcmpMessageType 11 tec = fmap TimeExceeded (word8ToEnumErr "TimeExceededCode" tec)
decodeIcmpMessageType 12 ppc = fmap ParameterProblem (word8ToEnumErr "ParameterProblemCode" ppc)
decodeIcmpMessageType 13 0   = return Timestamp
decodeIcmpMessageType 14 0   = return TimestampReply
decodeIcmpMessageType t  c   = return $ OtherMessage t c


word8ToEnumErr :: forall a . (Show a, Enum a, Bounded a)
               => String -> Word8 -> Either String a
word8ToEnumErr errStr w =
  let eMin = fromEnum (minBound :: a)
      eMax = fromEnum (maxBound :: a)
      idx = fromIntegral w
   in if (idx < eMin) || (idx > eMax)
      then Left $ "Unable to parse " <> errStr <> ", " <> (show w) <> " is out of [" <> (show eMin) <> ", " <> (show eMax) <> "] bounds."
      else Right $ toEnum idx



instance Binary ICMPMessageType where
  put mt = let (h1, h2) = encodeIcmpMessageType mt
            in do put h1
                  put h2

  get = do h1 <- get :: Get Word8
           h2 <- get :: Get Word8
           case decodeIcmpMessageType h1 h2
             of Left e   -> error e
                Right mt -> return mt



data ICMPHeader = ICMPHeader
    { icmpMessageType :: !ICMPMessageType
    , icmpCksum       :: !Word16
    , icmpHeaderData  :: !Word32
    }
    deriving (Eq, Show)


instance Binary ICMPHeader where
  put ICMPHeader{..} = do put icmpMessageType
                          put icmpCksum
                          put icmpHeaderData

  get = do t <- get :: Get ICMPMessageType
           c <- get :: Get Word16
           d <- get :: Get Word32
           return $ ICMPHeader t c d


data ICMPMessage = ICMPMessage
    { icmpHeader  :: !ICMPHeader
    , icmpPayload :: !ByteString
    }
    deriving (Eq, Show)


instance Binary ICMPMessage where
  put ICMPMessage{..} = do put icmpHeader
                           put icmpPayload

  get = do h     <- get :: Get ICMPHeader
           empty <- isEmpty
           p     <- if empty then return mempty else get :: Get ByteString
           return $ ICMPMessage h p


icmpVerifyChecksum :: ICMPMessage -> Bool
icmpVerifyChecksum m = m == (icmpAddMessageChecksum m)


icmpAddMessageChecksum :: ICMPMessage -> ICMPMessage
icmpAddMessageChecksum m@ICMPMessage{..} = m { icmpHeader = icmpHeader { icmpCksum = msgChecksum } }
  where msgChecksum = checksum $ encode $ m { icmpHeader = icmpHeader { icmpCksum = 0 } }

        -- From http://programatica.cs.pdx.edu/House/
        checksum :: ByteString -> Word16
        checksum bs = let bs' = (if (LB.length bs) `mod` 2 == 0 then bs else LB.snoc bs 0)
                          ws = runGet listOfWord16 bs'
                          total = sum (map fromIntegral ws) :: Word32
                       in complement (fromIntegral total + fromIntegral (total `shiftR` 16))

        listOfWord16 :: Get [Word16]
        listOfWord16 = do empty <- isEmpty
                          if empty
                          then return []
                          else do v <- getWord16be
                                  rest <- listOfWord16
                                  return (v : rest)
