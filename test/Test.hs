
import           Data.Either
import           Data.List
import           Net.ICMP.V4.Internal
import           Test.Framework (defaultMain, testGroup)
import           Test.Framework.Providers.HUnit
import           Test.Framework.Providers.QuickCheck2 (testProperty)
import           Test.HUnit
import           Test.QuickCheck
import           Data.ByteString.Lazy (ByteString)
import qualified Data.ByteString.Lazy as LB
import qualified Data.ByteString.Lazy.Char8 as C
import           Data.Binary


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
      return EchoReply
    , fmap DestinationUnreachable arbitrary
    , fmap Redirect arbitrary
    , return EchoRequest
    , return RouterAdvertisement
    , return RouterSolicitation
    , fmap TimeExceeded arbitrary
    , fmap ParameterProblem arbitrary
    , return Timestamp
    , return TimestampReply
    , do t <- suchThat arbitrary (>14)
         c <- arbitrary
         return $ OtherMessage t c
    ]

instance Arbitrary ICMPHeader where
  arbitrary = ICMPHeader <$> arbitrary <*> arbitrary <*> arbitrary

instance Arbitrary ICMPMessage where
  arbitrary = ICMPMessage <$> arbitrary <*> arbitrary


instance Arbitrary ByteString where
  arbitrary = fmap C.pack $ listOf arbitrary


main = defaultMain tests

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
        of Left x    -> False
           Right mt1 -> mt1 == mt


prop_encodeDecodeMessage :: ICMPMessage -> Bool
prop_encodeDecodeMessage m =
  let m1 = (decode . encode) m
   in m == m1


prop_verifyChecksum :: ICMPMessage -> Bool
prop_verifyChecksum m = icmpVerifyChecksum $ icmpAddMessageChecksum m
