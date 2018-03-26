

#import "RsaTool.h"
#import "NSData+FromString.h"
#import "BasicEncodingRules.h"
#import "NSData+Base64.h"
#import <UIKit/UIKit.h>

@implementation RsaTool

/**
 通过模数指数加密

 @param originalString 要加密的字符串
 @param mod 模数
 @param exp 指数
 @param padding padding
 @return 加密后的通过 base64 转换的字符串
 */
+ (NSString *)encryptString:(NSString *)originalString mod:(NSString *)mod exp:(NSString *)exp padding:(SecPadding)padding {
    NSData *EData = [NSData fromString:exp];
    NSData *NTempData = [NSData fromString:mod];
    NSMutableData *tempData = [[NSMutableData alloc] initWithCapacity:0];
    // 9.0 以上在模数前加00，https://github.com/StCredZero/SCZ-BasicEncodingRules-iOS/issues/6#issuecomment-136601437
    if ([[[UIDevice currentDevice] systemVersion] floatValue] >= 9.0) {
        const char fixByte = 0;
        [tempData appendBytes:&fixByte length:1];
    }

    [tempData appendData:NTempData];
    NSData *NData = [NSData dataWithData:tempData];
    
    // 生成公钥
    NSMutableArray *pubArray = [NSMutableArray arrayWithCapacity:0];
    [pubArray addObject:NData];
    [pubArray addObject:EData];
    NSData *pubData = [pubArray berData];
    
    // 包含公钥的 data 转换为 SecKeyRef
    SecKeyRef secKeyRef = [RsaTool publicSecKeyFromKeyBits:pubData];
    
    // 加密
    NSData *resultData = [RsaTool encryptString:originalString RSAPublicKey:secKeyRef padding:kSecPaddingNone];
    
    return [resultData base64EncodedString];
}

/**
 * encrypt with RSA public key
 *
 * padding = kSecPaddingPKCS1 / kSecPaddingNone
 *
 */
+ (NSData*)encryptString:(NSString*)original RSAPublicKey:(SecKeyRef)publicKey padding:(SecPadding)padding
{
    @try
    {
        size_t encryptedLength = SecKeyGetBlockSize(publicKey);
        uint8_t encrypted[encryptedLength];
        
        const char* cStringValue = [original UTF8String];
        OSStatus status = SecKeyEncrypt(publicKey,
                                        padding,
                                        (const uint8_t*)cStringValue,
                                        strlen(cStringValue),
                                        encrypted,
                                        &encryptedLength);
        if(status == noErr)
        {
            NSData* encryptedData = [[NSData alloc] initWithBytes:(const void*)encrypted length:encryptedLength];
            return encryptedData;
        }
        else
            return nil;
    }
    @catch (NSException * e)
    {
        //do nothing
        NSLog(@"exception: %@", [e reason]);
    }
    return nil;
}

// 包含公钥的 data 转 SecKeyRef
static NSString * const kTransfromIdenIdentifierPublic = @"kTransfromIdenIdentifierPublic";
+ (SecKeyRef)publicSecKeyFromKeyBits:(NSData *)givenData {
    
    NSData *peerTag = [NSData fromString:kTransfromIdenIdentifierPublic];
    
    OSStatus sanityCheck = noErr;
    SecKeyRef secKey = nil;
    
    NSMutableDictionary * queryKey = [[NSMutableDictionary alloc] init];
    [queryKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [queryKey setObject:peerTag forKey:(__bridge id)kSecAttrApplicationTag];
    [queryKey setObject:(id)kSecAttrKeyClassPublic forKey:(id)kSecAttrKeyClass];
    
    [queryKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    [queryKey setObject:givenData forKey:(__bridge id)kSecValueData];
    [queryKey setObject:@YES forKey:(__bridge id)kSecReturnRef];
    
    (void)SecItemDelete((__bridge CFDictionaryRef) queryKey);
    
    CFTypeRef result;
    sanityCheck = SecItemAdd((__bridge CFDictionaryRef) queryKey, &result);
    if (sanityCheck == errSecSuccess) {
        secKey = (SecKeyRef)result;
    }
    
    return secKey;
}

//For iOS 10 and later, public key or private key.
+ (SecKeyRef)RSASecKeyCreateWithDERData_iOS10:(NSData *)derData isPublic:(BOOL)isPublic{
    if (!derData) {
        return NULL;
    }
    
    SecKeyRef secKey = NULL;
#if __IPHONE_OS_VERSION_MAX_ALLOWED  >= 100000 //__IPHONE_10_0
    CFMutableDictionaryRef attributes = CFDictionaryCreateMutable(NULL, 0, NULL, NULL);
    if (attributes) {
        CFDictionaryAddValue(attributes, kSecAttrKeyType, kSecAttrKeyTypeRSA);
        CFDictionaryAddValue(attributes, kSecAttrKeyClass, isPublic ? kSecAttrKeyClassPublic : kSecAttrKeyClassPrivate);
        
        CFErrorRef error = NULL;
        if (@available(iOS 10.0, *)) {
            secKey = SecKeyCreateWithData((__bridge CFDataRef)derData, attributes, &error);
        } else {
            // Fallback on earlier versions
        }
        if (error) {
            NSLog(@"SecKeyCreateWithData %@",error);
        }
        CFRelease(attributes);
    }
#endif
    return secKey;
}

    
@end
