{-# OPTIONS_GHC -Wno-orphans #-}

import           Data.Binary
import           Data.ByteString.Lazy                 (ByteString)
import qualified Data.ByteString.Lazy.Char8           as C
import           Net.ICMP.V4.Internal
import           Test.Framework                       (Test, defaultMain,
                                                       testGroup)
import           Test.Framework.Providers.QuickCheck2 (testProperty)
import           Test.QuickCheck


instance Arbitrary DestinationUnreachableCode where
  arbitrary = arbitraryBoundedEnum

instance Arbitrary RedirectCode where
  arbitrary = arbitraryBoundedEnum

instance Arbitrary TimeExceededCode where
  arbitrary = arbitraryBoundedEnum

instance Arbitrary ParameterProblemCode where
  arbitrary = arbitraryBoundedEnum

instance Arbitrary ICMPMessageType where
  arbitrary = oneof [
      pure EchoReply
    , DestinationUnreachable <$> arbitrary
    , Redirect <$> arbitrary
    , pure EchoRequest
    , pure RouterAdvertisement
    , pure RouterSolicitation
    , TimeExceeded <$> arbitrary
    , ParameterProblem <$> arbitrary
    , pure Timestamp
    , pure TimestampReply
    , OtherMessage <$> suchThat arbitrary (>14)
                   <*> arbitrary
    ]

instance Arbitrary ICMPHeader where
  arbitrary = ICMPHeader <$> arbitrary <*> arbitrary <*> arbitrary

instance Arbitrary ICMPMessage where
  arbitrary = ICMPMessage <$> arbitrary <*> arbitrary


instance Arbitrary ByteString where
  arbitrary = C.pack <$> listOf arbitrary


main :: IO ()
main = defaultMain tests

tests :: [Test]
tests = [
    testGroup "ICMP" [
      testProperty "encode/decode ICMPMessageType" prop_encodeDecodeMessageType
    , testProperty "encode/decode ICMPMessage" prop_encodeDecodeMessage
    , testProperty "verify checksum" prop_verifyChecksum
    ]
  ]


prop_encodeDecodeMessageType :: ICMPMessageType -> Bool
prop_encodeDecodeMessageType mt =
  let (w1, w2) = encodeIcmpMessageType mt
      dMt = decodeIcmpMessageType w1 w2
   in case dMt
        of Left _    -> False
           Right mt1 -> mt1 == mt


prop_encodeDecodeMessage :: ICMPMessage -> Bool
prop_encodeDecodeMessage m =
  let m1 = (decode . encode) m
   in m == m1


prop_verifyChecksum :: ICMPMessage -> Bool
prop_verifyChecksum m = icmpVerifyChecksum $ icmpAddMessageChecksum m
