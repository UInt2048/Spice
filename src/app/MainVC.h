#ifndef MAINVC_H
#define MAINVC_H
#import <UIKit/UIKit.h>
#include <shared/common.h>

#if N41AP
#define COMPILED_DEVICE @"iPhone5,1 (iPhone 5, GSM)"
#elif N42AP
#define COMPILED_DEVICE @"iPhone5,2 (iPhone 5, Global)"
#elif N48AP
#define COMPILED_DEVICE @"iPhone5,3 (iPhone 5c, GSM)"
#elif N48AP
#define COMPILED_DEVICE @"iPhone5,4 (iPhone 5c, Global)"
#elif J71AP
#define COMPILED_DEVICE @"iPad4,1 (iPad Air 1st gen, Wi-Fi)"
#elif J72AP
#define COMPILED_DEVICE @"iPad4,2 (iPad Air 1st gen, cellular)"
#elif J73AP
#define COMPILED_DEVICE @"iPad4,3 (iPad Air 1st gen, China)"
#elif J85AP
#define COMPILED_DEVICE @"iPad4,4 (iPad mini 2, Wi-Fi)"
#elif J86AP
#define COMPILED_DEVICE @"iPad4,5 (iPad mini 2, cellular)"
#elif J87AP
#define COMPILED_DEVICE @"iPad4,6 (iPad mini 2, China)"
#elif J85mAP
#define COMPILED_DEVICE @"iPad4,7 (iPad mini 3, Wi-Fi)"
#elif J86mAP
#define COMPILED_DEVICE @"iPad4,8 (iPad mini 3, cellular)"
#elif J87mAP
#define COMPILED_DEVICE @"iPad4,9 (iPad mini 3, China)"
#elif J96AP
#define COMPILED_DEVICE @"iPad5,1 (iPad mini 4, Wi-Fi)"
#elif J97AP
#define COMPILED_DEVICE @"iPad5,2 (iPad mini 4, cellular)"
#elif J81AP
#define COMPILED_DEVICE @"iPad5,3 (iPad Air 2, Wi-Fi)"
#elif J82AP
#define COMPILED_DEVICE @"iPad5,4 (iPad Air 2, cellular)"
#elif J127AP
#define COMPILED_DEVICE @"iPad6,3 (iPad Pro 9.7, Wi-Fi)"
#elif J128AP
#define COMPILED_DEVICE @"iPad6,4 (iPad Pro 9.7, cellular)"
#elif J98aAP
#define COMPILED_DEVICE @"iPad6,7 (iPad Pro 12.9, Wi-Fi)"
#elif J99aAP
#define COMPILED_DEVICE @"iPad6,8 (iPad Pro 12.9, cellular)"
#elif (J71sAP | J71tAP)
#define COMPILED_DEVICE @"iPad6,11 (iPad 5, Wi-Fi)"
#elif (J72sAP | J72tAP)
#define COMPILED_DEVICE @"iPad6,12 (iPad 5, cellular)"
#elif N51AP
#define COMPILED_DEVICE @"iPhone6,1 (iPhone 5s, GSM)"
#elif N53AP
#define COMPILED_DEVICE @"iPhone6,2 (iPhone 5s, Global)"
#elif N56AP
#define COMPILED_DEVICE @"iPhone7,1 (iPhone 6 Plus)"
#elif N61AP
#define COMPILED_DEVICE @"iPhone7,2 (iPhone 6)"
#elif N71AP
#define COMPILED_DEVICE @"iPhone8,1 (iPhone 6s)"
#elif (N66AP | N66mAP)
#define COMPILED_DEVICE @"iPhone8,2 (iPhone 6s Plus)"
#elif (N69AP | N69uAP)
#define COMPILED_DEVICE @"iPhone8,4 (iPhone SE 1st gen)"
#elif N102AP
#define COMPILED_DEVICE @"iPod7,1 (iPod touch 6th gen)"
#else
#define COMPILED_DEVICE @"unknown device"
#endif

#if IOS_10_3_4
#define COMPILED_IOS @"iOS 10.3.4"
#elif IOS_11_0
#define COMPILED_IOS @"iOS 11.0"
#elif IOS_11_0_1
#define COMPILED_IOS @"iOS 11.0.1"
#elif IOS_11_0_2
#define COMPILED_IOS @"iOS 11.0.2"
#elif IOS_11_0_3
#define COMPILED_IOS @"iOS 11.0.3"
#elif IOS_11_1
#define COMPILED_IOS @"iOS 11.1"
#elif IOS_11_1_1
#define COMPILED_IOS @"iOS 11.1.1"
#elif IOS_11_1_2
#define COMPILED_IOS @"iOS 11.1.2"
#elif IOS_11_2
#define COMPILED_IOS @"iOS 11.2"
#elif IOS_11_2_1
#define COMPILED_IOS @"iOS 11.2.1"
#elif IOS_11_2_2
#define COMPILED_IOS @"iOS 11.2.2"
#elif IOS_11_2_5
#define COMPILED_IOS @"iOS 11.2.5"
#elif IOS_11_2_6
#define COMPILED_IOS @"iOS 11.2.6"
#elif IOS_11_3
#define COMPILED_IOS @"iOS 11.3"
#elif IOS_11_3_1
#define COMPILED_IOS @"iOS 11.3.1"
#elif IOS_11_4
#define COMPILED_IOS @"iOS 11.4"
#elif IOS_11_4_1
#define COMPILED_IOS @"iOS 11.4.1"
#else
#define COMPILED_IOS @"unknown iOS"
#endif

@interface MainVC : UIViewController

@property (nonatomic, strong) UITextView *textView;

- (void)showLog:(NSString *)log;

- (id)init;

- (void)actionJailbreak;

@end
#endif
