#import <UIKit/UIKit.h>

@interface MainVC : UIViewController

@property (nonatomic, strong) UITextView *textView;

- (void)showLog:(NSString *)log;

- (id)init;

- (void)actionJailbreak;

@end
