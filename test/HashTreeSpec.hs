{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE OverloadedStrings #-}

module HashTreeSpec where

import Crypto.Hash
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.ByteString.Base64
import Data.ByteString.Char8 ()
import Data.HashTree
import Data.HashTree.Internal
import Data.List (nub)
import Data.Maybe
import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck


newtype Input = Input [ByteString] deriving Show -- non empty list

instance Arbitrary ByteString where
    arbitrary = BS.pack <$> listOf arbitrary -- Gen Word8

instance Arbitrary Input where
    arbitrary = Input . getNonEmpty <$> arbitrary -- Gen (NonEmptyList ByteString)

spec :: Spec
spec = do
    let set = defaultSettings
    describe "info" $ do
        prop "The root hash of 1-size tree is equal to the leaf hash" $ \bs ->
            let mht = add (bs :: ByteString) $ empty set
                h1 = snd $ info mht
                h2 = hash1 set bs
            in h1 == h2
    describe "fromList" $ do
        prop "create a perfectly branched tree" $ \(Input bss) ->
            let Just ht = currentHead $ fromList set bss
                ht' = toHashTree set $ nub bss
            in ht == ht'
    describe "verifyInclusionProof" $ do
        it "can verify the certificate transparency" $
            verifyInclusionProof set dl d2 iProof `shouldBe` True
        prop "can verify for a good target" $ \(Input bss0) x0 y0 ->
            let bss = nub bss0
                mht = fromList set bss
                len = length bss
                x0' = adjust x0 len
                y0' = adjust y0 len
                (i,tsiz)
                   | x0' < y0' = (x0',y0')
                   | x0' > y0' = (y0',x0')
                   | otherwise = (x0',y0'+1)
                target = bss !! i
                leafDigest = hash1 set target
                proof = fromJust $ generateInclusionProof leafDigest tsiz mht
                Just rootDigest = digest tsiz mht
            in verifyInclusionProof set leafDigest rootDigest proof
    describe "verifyConsistencyProof" $ do
        it "can verify the certificate transparency" $
            verifyConsistencyProof set d1 d2 cProof `shouldBe` True
        prop "can verify" $ \(Input bss) m0 n0 ->
            let mht = fromList set bss
                siz = size mht
                m0' = adjust m0 siz
                n0' = adjust n0 siz
                (m,n) = if m0' <= n0' then (m0',n0') else (n0',m0')
                proof = fromJust $ generateConsistencyProof m n mht
                Just dm = digest m mht
                Just dn = digest n mht
            in verifyConsistencyProof set dm dn proof

adjust :: Int -> Int -> Int
adjust x b
  | x < 0     = negate x `mod` b
  | otherwise = x `mod` b

toDigest :: ByteString -> Digest SHA256
toDigest x = d
  where
    Right r = decode x
    Just d = digestFromByteString r


{-
% wget https://ct.googleapis.com/icarus/ct/v1/get-sth
{"tree_size":129596132,"timestamp":1508198131197,"sha256_root_hash":"qyJv/TObheataX8uFjAJsR+dJtJgNlfjzTe5CX8Ej2s=","tree_head_signature":"BAMASDBGAiEAhtcpfpVSKRuZOxEMpPRRiu5nPdd8UL3JnQBk23Zrk/ACIQD+n4YSigh3o1KaJvBTvJkcmq2CW5QtrIBdI2oDiItN1A=="}
-}
d1 :: Digest SHA256
d1 = toDigest "qyJv/TObheataX8uFjAJsR+dJtJgNlfjzTe5CX8Ej2s="

{-
% wget https://ct.googleapis.com/icarus/ct/v1/get-sth
{"tree_size":129721434,"timestamp":1508216080417,"sha256_root_hash":"jhnkzC7e95jLNBJSiQRnuH2sXYfpY6sASO3ezfUBU0w=","tree_head_signature":"BAMARzBFAiBkiNQdBXnYQLwbcSxPYjvKYatziAbADq124OifIeZ2oQIhAOzYM60DNII1ILtWDMvCPcGqTapkb/Ru4KIJJwdTi+dg"}
-}
d2 :: Digest SHA256
d2 = toDigest "jhnkzC7e95jLNBJSiQRnuH2sXYfpY6sASO3ezfUBU0w="

{-
% wget 'https://ct.googleapis.com/icarus/ct/v1/get-sth-consistency?first=129596132&second=129721434'
{"consistency":["5mrKRX9GRLriSIAtkX0kdvlnjt/f+P0vTrhmzOdhnzs=","VEqL3Z55VZTVRp45WX7gTdcwxOorltn+uCQpHjv9rjE=","2Euj4VXixjEAGj9p23OMo+ciB1tQ2KXH97TkWgcZLpI=","rG0l6AHdk3TRkgAnwTK1Ys5kU7uuKRkMQSkrES0ocj0=","JSxii5BAGCuwifRNIgIsarVA/aSC/QJNv4kfT9zii3Y=","WPaErDHN/lYCuv8TsvosmAsIDbEOfPNZ/LxqLvuQcdY=","HjN1fCoS6OYw8VH+DAcQPQkCjksWljkvr3AJiZTsi6Y=","liuu+DeQohOzAyQadR3imE0SLo8pSsv9K0Y9f1dGrwA=","oUQV+oip0wozcwv4mmMv4MrP545ugwXDIMU6HkZrfl0=","V9BPc7aq1Sq1XwFV3gMx7/9Wv+8l/81S5Gb+bDriRZE=","h3PJZDxVUsGMPBMEaJsQnqAVjlpuxUPGAUfYCY6TkWY=","Rj09QnLzZ2MmyKjJYkcSO8Ko6lGhgwrnOydn+RdHdeI=","Dc7oYAljc9VEYI8JuvYVyJtTHP8uW7igIKVqnWXgvFs=","tJfBVa+YE0GK8T1L74hkkGmT3QO+mznMf+XrKnS3YOE=","V9uRJUhCpCMwss1i4c85X5ceJnNePXdjAVrxtU6EezY=","nf6Yq8xIs56hgor/mk30dvpaUO1/1w+MUlz8thiEb3o=","SEVW3kh8HQ9Za+LjCoGaAkbbUfYmiwNs3SDasWKS6xo=","96r7XxdWTPAZSygfov9mTTd4Gs6chZfdkznd8HAmzKc=","t6OBvH84uFTwEubekO8rdcv+AlqPcpuZX9pwLYopKGg=","nl6nrmkzk5qSYBiUHN609SD8IH3HuTPYR6r1YWKtWag=","NbPA38XBZUXC5ca/cNcU/mNhq31qg2okTS3kJdptnxg=","Ur4mOpiyDl1Zq/MH/SGszUlBP7jmOfupNVodMT6Mg2M=","LUTvZyrtuEoSL7PNqR2Iv2FbcbtI5lQrq5/97sMFIsU=","Bh+FIkHuIdFAcvCYOTlkKMxR15aDaaT9UlUsrCeuLUY="]}
-}
cProof :: ConsistencyProof SHA256
cProof = ConsistencyProof 129596132 129721434 cs
  where
    bs = ["5mrKRX9GRLriSIAtkX0kdvlnjt/f+P0vTrhmzOdhnzs="
         ,"VEqL3Z55VZTVRp45WX7gTdcwxOorltn+uCQpHjv9rjE="
         ,"2Euj4VXixjEAGj9p23OMo+ciB1tQ2KXH97TkWgcZLpI="
         ,"rG0l6AHdk3TRkgAnwTK1Ys5kU7uuKRkMQSkrES0ocj0="
         ,"JSxii5BAGCuwifRNIgIsarVA/aSC/QJNv4kfT9zii3Y="
         ,"WPaErDHN/lYCuv8TsvosmAsIDbEOfPNZ/LxqLvuQcdY="
         ,"HjN1fCoS6OYw8VH+DAcQPQkCjksWljkvr3AJiZTsi6Y="
         ,"liuu+DeQohOzAyQadR3imE0SLo8pSsv9K0Y9f1dGrwA="
         ,"oUQV+oip0wozcwv4mmMv4MrP545ugwXDIMU6HkZrfl0="
         ,"V9BPc7aq1Sq1XwFV3gMx7/9Wv+8l/81S5Gb+bDriRZE="
         ,"h3PJZDxVUsGMPBMEaJsQnqAVjlpuxUPGAUfYCY6TkWY="
         ,"Rj09QnLzZ2MmyKjJYkcSO8Ko6lGhgwrnOydn+RdHdeI="
         ,"Dc7oYAljc9VEYI8JuvYVyJtTHP8uW7igIKVqnWXgvFs="
         ,"tJfBVa+YE0GK8T1L74hkkGmT3QO+mznMf+XrKnS3YOE="
         ,"V9uRJUhCpCMwss1i4c85X5ceJnNePXdjAVrxtU6EezY="
         ,"nf6Yq8xIs56hgor/mk30dvpaUO1/1w+MUlz8thiEb3o="
         ,"SEVW3kh8HQ9Za+LjCoGaAkbbUfYmiwNs3SDasWKS6xo="
         ,"96r7XxdWTPAZSygfov9mTTd4Gs6chZfdkznd8HAmzKc="
         ,"t6OBvH84uFTwEubekO8rdcv+AlqPcpuZX9pwLYopKGg="
         ,"nl6nrmkzk5qSYBiUHN609SD8IH3HuTPYR6r1YWKtWag="
         ,"NbPA38XBZUXC5ca/cNcU/mNhq31qg2okTS3kJdptnxg="
         ,"Ur4mOpiyDl1Zq/MH/SGszUlBP7jmOfupNVodMT6Mg2M="
         ,"LUTvZyrtuEoSL7PNqR2Iv2FbcbtI5lQrq5/97sMFIsU="
         ,"Bh+FIkHuIdFAcvCYOTlkKMxR15aDaaT9UlUsrCeuLUY="
         ]
    cs = map toDigest bs

{-
% wget 'https://ct.googleapis.com/icarus/ct/v1/get-entry-and-proof?leaf_index=120000000&tree_size=129721434'
{"leaf_input":"AAAAAAFexROk9wAAAAUdMIIFGTCCBAGgAwIBAgISBC/2U32dBHf/8H9aIod2qqPFMA0GCSqGSIb3DQEBCwUAMEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQDExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0xNzA5MjcxOTQzMDBaFw0xNzEyMjYxOTQzMDBaMBsxGTAXBgNVBAMTEGdlbS1qZXdlbGVycy5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDB61H4Kvny8rX0gBuvPciX9VpPzfkdYHjRwmZLU3uj3awfN+4qouO7ipz9Cyz1saCI53NXisHr3lttxAF1ISnidvywgRyaO9G0BVAn6Tl5zarOhwrf56wopfyEGaHfpyO8dCV5nfNWM99gbmrcJgWqs5/7Np9L+Y0ZMah751X6oZsJqKSs6FCUbAtyeAhXBQMuSOqkd85nObSpnf2W0CAfWYy66VPbDL8OAhq0A/3U+gh9ThWCAPPn9pVghazBKsSL+c1KW84xsXuHWkkgLjJ3f/oL9FPTzNBfqYzzeuAVAEwazYXPyEu5SlbdqzDi1Lesp0+2yoMO9h7MWy9Mom05AgMBAAGjggImMIICIjAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFDQaIW5tEaFbKN9qRmVdZEk2eB4GMB8GA1UdIwQYMBaAFKhKamMEfd265tE5t6ZFZe/zqOyhMG8GCCsGAQUFBwEBBGMwYTAuBggrBgEFBQcwAYYiaHR0cDovL29jc3AuaW50LXgzLmxldHNlbmNyeXB0Lm9yZzAvBggrBgEFBQcwAoYjaHR0cDovL2NlcnQuaW50LXgzLmxldHNlbmNyeXB0Lm9yZy8wMQYDVR0RBCowKIIQZ2VtLWpld2VsZXJzLmNvbYIUd3d3LmdlbS1qZXdlbGVycy5jb20wgf4GA1UdIASB9jCB8zAIBgZngQwBAgEwgeYGCysGAQQBgt8TAQEBMIHWMCYGCCsGAQUFBwIBFhpodHRwOi8vY3BzLmxldHNlbmNyeXB0Lm9yZzCBqwYIKwYBBQUHAgIwgZ4MgZtUaGlzIENlcnRpZmljYXRlIG1heSBvbmx5IGJlIHJlbGllZCB1cG9uIGJ5IFJlbHlpbmcgUGFydGllcyBhbmQgb25seSBpbiBhY2NvcmRhbmNlIHdpdGggdGhlIENlcnRpZmljYXRlIFBvbGljeSBmb3VuZCBhdCBodHRwczovL2xldHNlbmNyeXB0Lm9yZy9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQsFAAOCAQEAMMIZaoRMUdLpIyc7TmFmjz8h9q24xnwY04J61CALDVV8c8IjzRwuheqcCzOmBAfI4ejBnAb3wxIYIq/FlYmWbLHEdpOviPFgyV6uskNGGAyEWjU+ah3E9NXxJ2+/h/GmDOLk3D6aXeLyFpZr1nAhl9+Sr+Gj/gWijiAhpKKT/al73u4ZG8exhsRlfTr84Mtgn29NwolMAQ5anMuLgk3d7YTOpsi602vQTyEAj5G7SUryBvf+lYhDvyZwLkbEqaQnuUvHu2uLGbtRb002CAptZeqTLQ84hIjS1JJ5YZgdEtPlbUqduuR6CB3nIA6cKdLKyoTw3Yxwh9Xeowe6OEVEIwAA","extra_data":"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","audit_path":["xNXDvcL4JYFTwHXfnl0an0vyCjS0am5+B8dxDozc5ag=","LJc7lPt79J4pgFqY0hbGYXZi401EnFVix2vFUSovrB8=","QFcF13awbePeLAqSfFoNB6cYYU40wwY7aLYQXk/ss/A=","Wlc9EJxIODGOKavf7zXfPOrymuWwviwGUI8K6h9EBFQ=","aigt2QVYyMjXSLFAhuaEvBmqctsFVKFZEgtJYl/gPL8=","DALuGNF8WzgEgdYT34KFCzbRlV+wx5Ie1jrUsfJS+Jo=","wfZyGm8U+u587alYY91O5sOCVVMPqNA1wwst8/CLsWA=","frRFNtjphdfOKw0X1I1AZfU6yuCMZ+/bC9sHXg6L4DQ=","5DgE84Ns18cCD9zOiiPUuUP17nOmxMm4copkw2MHY9g=","ggacmAKa8hnTxehF0WUAbknaQk1Ks6c33x2g/zOVWgw=","I1YeaNL1rb0YNDCb7Xe9VPosJKP0fv3msScVnNsn4PA=","BPVDHS1+mcuIEsShBg19U6UCwIQKJwRZeXIECFA6zcw=","7smS/3DRbnKci59UoBg7xDf+NlAVGAZ2qtG4ILaAK/Q=","75SJNIAzyepGCUnfvUTVrZSddSfWaSxxXXmBiHewa8g=","YxHvS/I+2i1yJLilSU/ZKjyr5jc5ABhuU4Wh6H+oBUY=","7DBov9qK6s/uy8g0iL//5A97ZAELOSE6SjGMGVBK8dY=","JsXCAk0Ztn8YZFmyfUkuJYzAzlV70D+mefthbBvRjaY=","YHBP2MPkXLUeRIMQTdQ9LVxolKbn1onla0Uedgp1x+Y=","yE4z+aQ1n/7sLJRG8jM5xKLq+JlHg3GoN3ApPovnh/o=","fwU2Yg7p+8ACX6v3e7xiJGwDeYo0b+33hbxy+KMdMfA=","5gj0c1LVruisvtT8VA1J9IeWyRaTf0+dwuLnamseTl8=","HQec1yNY1oQtctj/ZfpEtDZZf3aT19Qdo4aaBPvaT+I=","FPtmqvOXlhE5gi/rc/sfWQpvLT7tPfHKJiSCEgmf3Hk=","EtTWrgka0wMLdqJ4oFojyDzjsuLoSyZpyzKzff+yFxU=","Ur4mOpiyDl1Zq/MH/SGszUlBP7jmOfupNVodMT6Mg2M=","LUTvZyrtuEoSL7PNqR2Iv2FbcbtI5lQrq5/97sMFIsU=","Bh+FIkHuIdFAcvCYOTlkKMxR15aDaaT9UlUsrCeuLUY="]}
-}

dl :: Digest SHA256
dl = hash1 defaultSettings r
  where
   Right r = decode "AAAAAAFexROk9wAAAAUdMIIFGTCCBAGgAwIBAgISBC/2U32dBHf/8H9aIod2qqPFMA0GCSqGSIb3DQEBCwUAMEoxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MSMwIQYDVQQDExpMZXQncyBFbmNyeXB0IEF1dGhvcml0eSBYMzAeFw0xNzA5MjcxOTQzMDBaFw0xNzEyMjYxOTQzMDBaMBsxGTAXBgNVBAMTEGdlbS1qZXdlbGVycy5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDB61H4Kvny8rX0gBuvPciX9VpPzfkdYHjRwmZLU3uj3awfN+4qouO7ipz9Cyz1saCI53NXisHr3lttxAF1ISnidvywgRyaO9G0BVAn6Tl5zarOhwrf56wopfyEGaHfpyO8dCV5nfNWM99gbmrcJgWqs5/7Np9L+Y0ZMah751X6oZsJqKSs6FCUbAtyeAhXBQMuSOqkd85nObSpnf2W0CAfWYy66VPbDL8OAhq0A/3U+gh9ThWCAPPn9pVghazBKsSL+c1KW84xsXuHWkkgLjJ3f/oL9FPTzNBfqYzzeuAVAEwazYXPyEu5SlbdqzDi1Lesp0+2yoMO9h7MWy9Mom05AgMBAAGjggImMIICIjAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFDQaIW5tEaFbKN9qRmVdZEk2eB4GMB8GA1UdIwQYMBaAFKhKamMEfd265tE5t6ZFZe/zqOyhMG8GCCsGAQUFBwEBBGMwYTAuBggrBgEFBQcwAYYiaHR0cDovL29jc3AuaW50LXgzLmxldHNlbmNyeXB0Lm9yZzAvBggrBgEFBQcwAoYjaHR0cDovL2NlcnQuaW50LXgzLmxldHNlbmNyeXB0Lm9yZy8wMQYDVR0RBCowKIIQZ2VtLWpld2VsZXJzLmNvbYIUd3d3LmdlbS1qZXdlbGVycy5jb20wgf4GA1UdIASB9jCB8zAIBgZngQwBAgEwgeYGCysGAQQBgt8TAQEBMIHWMCYGCCsGAQUFBwIBFhpodHRwOi8vY3BzLmxldHNlbmNyeXB0Lm9yZzCBqwYIKwYBBQUHAgIwgZ4MgZtUaGlzIENlcnRpZmljYXRlIG1heSBvbmx5IGJlIHJlbGllZCB1cG9uIGJ5IFJlbHlpbmcgUGFydGllcyBhbmQgb25seSBpbiBhY2NvcmRhbmNlIHdpdGggdGhlIENlcnRpZmljYXRlIFBvbGljeSBmb3VuZCBhdCBodHRwczovL2xldHNlbmNyeXB0Lm9yZy9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQsFAAOCAQEAMMIZaoRMUdLpIyc7TmFmjz8h9q24xnwY04J61CALDVV8c8IjzRwuheqcCzOmBAfI4ejBnAb3wxIYIq/FlYmWbLHEdpOviPFgyV6uskNGGAyEWjU+ah3E9NXxJ2+/h/GmDOLk3D6aXeLyFpZr1nAhl9+Sr+Gj/gWijiAhpKKT/al73u4ZG8exhsRlfTr84Mtgn29NwolMAQ5anMuLgk3d7YTOpsi602vQTyEAj5G7SUryBvf+lYhDvyZwLkbEqaQnuUvHu2uLGbtRb002CAptZeqTLQ84hIjS1JJ5YZgdEtPlbUqduuR6CB3nIA6cKdLKyoTw3Yxwh9Xeowe6OEVEIwAA"

iProof :: InclusionProof SHA256
iProof = InclusionProof 120000000 129721434 is
  where
    bs = ["xNXDvcL4JYFTwHXfnl0an0vyCjS0am5+B8dxDozc5ag=","LJc7lPt79J4pgFqY0hbGYXZi401EnFVix2vFUSovrB8=","QFcF13awbePeLAqSfFoNB6cYYU40wwY7aLYQXk/ss/A=","Wlc9EJxIODGOKavf7zXfPOrymuWwviwGUI8K6h9EBFQ=","aigt2QVYyMjXSLFAhuaEvBmqctsFVKFZEgtJYl/gPL8=","DALuGNF8WzgEgdYT34KFCzbRlV+wx5Ie1jrUsfJS+Jo=","wfZyGm8U+u587alYY91O5sOCVVMPqNA1wwst8/CLsWA=","frRFNtjphdfOKw0X1I1AZfU6yuCMZ+/bC9sHXg6L4DQ=","5DgE84Ns18cCD9zOiiPUuUP17nOmxMm4copkw2MHY9g=","ggacmAKa8hnTxehF0WUAbknaQk1Ks6c33x2g/zOVWgw=","I1YeaNL1rb0YNDCb7Xe9VPosJKP0fv3msScVnNsn4PA=","BPVDHS1+mcuIEsShBg19U6UCwIQKJwRZeXIECFA6zcw=","7smS/3DRbnKci59UoBg7xDf+NlAVGAZ2qtG4ILaAK/Q=","75SJNIAzyepGCUnfvUTVrZSddSfWaSxxXXmBiHewa8g=","YxHvS/I+2i1yJLilSU/ZKjyr5jc5ABhuU4Wh6H+oBUY=","7DBov9qK6s/uy8g0iL//5A97ZAELOSE6SjGMGVBK8dY=","JsXCAk0Ztn8YZFmyfUkuJYzAzlV70D+mefthbBvRjaY=","YHBP2MPkXLUeRIMQTdQ9LVxolKbn1onla0Uedgp1x+Y=","yE4z+aQ1n/7sLJRG8jM5xKLq+JlHg3GoN3ApPovnh/o=","fwU2Yg7p+8ACX6v3e7xiJGwDeYo0b+33hbxy+KMdMfA=","5gj0c1LVruisvtT8VA1J9IeWyRaTf0+dwuLnamseTl8=","HQec1yNY1oQtctj/ZfpEtDZZf3aT19Qdo4aaBPvaT+I=","FPtmqvOXlhE5gi/rc/sfWQpvLT7tPfHKJiSCEgmf3Hk=","EtTWrgka0wMLdqJ4oFojyDzjsuLoSyZpyzKzff+yFxU=","Ur4mOpiyDl1Zq/MH/SGszUlBP7jmOfupNVodMT6Mg2M=","LUTvZyrtuEoSL7PNqR2Iv2FbcbtI5lQrq5/97sMFIsU=","Bh+FIkHuIdFAcvCYOTlkKMxR15aDaaT9UlUsrCeuLUY="]
    is = map toDigest bs
