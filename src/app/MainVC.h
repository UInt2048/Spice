#import <UIKit/UIKit.h>
NSString* deviceName();

@interface MainVC : UIViewController

@property (nonatomic, strong) UITextView *textView;

- (void)showLog:(NSString *)log;

- (id)init;

- (void)actionJailbreak;

- (void)actionFailed;

- (void)exploitSucceeded;

- (void)exploitFailed;

@end
