
#import <Foundation/Foundation.h>

@interface RsaTool : NSObject

/**
 通过模数指数加密
 
 @param originalString 要加密的字符串
 @param mod 模数
 @param exp 指数
 @param padding padding
 @return 加密后的通过 base64 转换的字符串
 */
+ (NSString *)encryptString:(NSString *)originalString mod:(NSString *)mod exp:(NSString *)exp padding:(SecPadding)padding;

/**
 使用公钥加密

 @param original 要加密的字符串
 @param publicKey 公钥
 @param padding padding
 @return 加密后的data
 */
+ (NSData*)encryptString:(NSString*)original RSAPublicKey:(SecKeyRef)publicKey padding:(SecPadding)padding;

@end
