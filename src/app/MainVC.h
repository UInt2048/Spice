#ifndef MAINVC_H
#define MAINVC_H
#import <UIKit/UIKit.h>

NSString* deviceName(void);

@interface MainVC : UIViewController

@property (nonatomic, strong) UITextView* textView;

- (void)showLog:(NSString*)log;

- (id)init;

- (void)actionJailbreak;

- (void)actionFailed;

- (void)exploitSucceeded;

- (void)exploitFailed;

@end

#endif
