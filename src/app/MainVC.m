#import <CoreFoundation/CoreFoundation.h>
#include <UIKit/UIDevice.h>

#include <shared/common.h>
#include <shared/offsets.h>
#include <untether/offsets.h>

#include <shared/jailbreak.h> // for jailbreak function
#include <shared/utils.h> // for respring function

#import "MainVC.h"

#define UICOLOR(r, g, b, a) [UIColor colorWithRed:(CGFloat)(r / 255.0) green:(CGFloat)(g / 255.0) blue:(CGFloat)(b / 255.0) alpha:(CGFloat)a]
#define CGCOLOR(r, g, b, a) (id) UICOLOR(r, g, b, a).CGColor
#define CONSTRAINT(subview, x, y)                                                                                                                                                                                                                     \
    do {                                                                                                                                                                                                                                              \
        [self.view addSubview:subview];                                                                                                                                                                                                               \
        [self.view addConstraint:[NSLayoutConstraint constraintWithItem:subview attribute:NSLayoutAttributeCenterX relatedBy:NSLayoutRelationEqual toItem:self.view attribute:NSLayoutAttributeCenterX multiplier:(CGFloat)x constant:(CGFloat)0.0]]; \
        [self.view addConstraint:[NSLayoutConstraint constraintWithItem:subview attribute:NSLayoutAttributeCenterY relatedBy:NSLayoutRelationEqual toItem:self.view attribute:NSLayoutAttributeCenterY multiplier:(CGFloat)y constant:(CGFloat)0.0]]; \
    } while (0)

#define addButton(button, title, color1, color2, fontSize, selector, x, y)                    \
    do {                                                                                      \
        button.translatesAutoresizingMaskIntoConstraints = NO;                                \
        [button setTitle:title forState:UIControlStateNormal];                                \
        [button setTitleColor:color1 forState:UIControlStateNormal];                          \
        [button setTitleColor:color2 forState:UIControlStateHighlighted];                     \
        [button setBackgroundColor:UICOLOR(0, 0, 0, 0.0)];                                    \
        button.titleLabel.font = [UIFont systemFontOfSize:fontSize];                          \
        [button addTarget:self action:selector forControlEvents:UIControlEventTouchUpInside]; \
        CONSTRAINT(button, x, y);                                                             \
    } while (0)

#define addLabel(label, title, color, fontSize, x, y)         \
    do {                                                      \
        label.translatesAutoresizingMaskIntoConstraints = NO; \
        label.text = title;                                   \
        label.textColor = color;                              \
        [label setBackgroundColor:UICOLOR(0, 0, 0, 0.0)];     \
        label.font = [UIFont systemFontOfSize:fontSize];      \
        CONSTRAINT(label, x, y);                              \
    } while (0)

#define addTextView(textView, title, color, fontSize, frameRect, centerPos)      \
    do {                                                                         \
        textView.translatesAutoresizingMaskIntoConstraints = NO;                 \
        textView.backgroundColor = UICOLOR(0, 0, 0, 0.7);                        \
        textView.text = title;                                                   \
        textView.textColor = color;                                              \
        textView.editable = NO;                                                  \
        textView.scrollEnabled = YES;                                            \
        textView.textContainerInset = UIEdgeInsetsMake(0, 15, 15, 15);           \
        textView.font = [UIFont fontWithName:@"Courier" size:(CGFloat)fontSize]; \
        textView.frame = frameRect;                                              \
        textView.center = centerPos;                                             \
        [self.view addSubview:textView];                                         \
    } while (0)

static void sendLog(void* controller, NSString* log)
{
    [(MainVC*)controller showLog:log];
}

@implementation MainVC

static UIButton* jbButton;
static UILabel *spiceLabel, *titleLabel;
static bool hasJailbroken = false;
static uint32_t jailbreakFlags = 0;

- (void)showLog:(NSString*)log
{
    NSLog(@"Entered MainVC log function to log: \"%@\"", log);
    if (![NSThread isMainThread]) {
        dispatch_async(dispatch_get_main_queue(), ^{
            [self showLog:log];
        });
        return;
    }
    NSLog(@"Entered on main thread to log: \"%@\"", log);

    self.textView.text = [self.textView.text stringByAppendingString:[NSString stringWithFormat:@"> %@\n", log]];
    [UIView performWithoutAnimation:^{
        [self.textView scrollRangeToVisible:NSMakeRange(self.textView.text.length, 0)];
    }];
}

- (id)init
{
    LOG("Entered Spice init method");

    id ret = [super initWithNibName:nil bundle:nil];
    self.tabBarItem = [[UITabBarItem alloc] initWithTitle:@"Jailbreak" image:nil tag:1];
    self.textView = [[UITextView alloc] init];
    return ret;
}

- (void)viewWillAppear:(BOOL)animated
{
    [super viewWillAppear:animated];
    CAGradientLayer* gradient = [CAGradientLayer layer];
    gradient.frame = self.view.bounds;
    gradient.colors = @[ CGCOLOR(92, 201, 59, 1.0), CGCOLOR(42, 100, 25, 1.0) ];
    [self.view.layer insertSublayer:gradient atIndex:0];
}

// Load everything

- (NSString*)getInitialLogText
{
    NSString* text;

    offsets_t* off1 = malloc(sizeof(offsets_t));
    memset(off1, 0, sizeof(offsets_t));
    offset_struct_t* off2 = malloc(sizeof(offset_struct_t));
    memset(off2, 0, sizeof(offset_struct_t));

    if (populate_offsets(off1, off2)) {
        text = [NSString stringWithFormat:@"[*] Using offsets for %@ on %@\n", deviceName(), [[UIDevice currentDevice] systemVersion]];
        if (off1->flags & FLAG_VERIFIED) {
            text = [text stringByAppendingString:[NSString stringWithFormat:@"[*] Offsets verified for %@ on %@\n", deviceName(), [[UIDevice currentDevice] systemVersion]]];
        } else {
            text = [text stringByAppendingString:[NSString stringWithFormat:@"[*] Offsets unverified, please inform if it functions\n", deviceName(), [[UIDevice currentDevice] systemVersion]]];
        }
    } else {
        text = [NSString stringWithFormat:@"[*] Offsets not found for %@ on %@\n", deviceName(), [[UIDevice currentDevice] systemVersion]];
        [jbButton setTitle:@"No offsets" forState:UIControlStateNormal];
        [jbButton removeTarget:nil action:NULL forControlEvents:UIControlEventAllEvents];
        [jbButton addTarget:self action:@selector(actionFailed) forControlEvents:UIControlEventTouchUpInside];
    }

    return [text stringByAppendingString:[NSString stringWithFormat:@"[*] Booted at %@\n", [[[NSISO8601DateFormatter alloc] init] stringFromDate:[NSDate dateWithTimeIntervalSince1970:bootsec()]]]];
}

- (void)loadView
{
    [super loadView];

    jbButton = [UIButton buttonWithType:UIButtonTypeSystem];
    addButton(jbButton, @"Jailbreak", UICOLOR(110, 59, 38, 1.0), UICOLOR(35, 75, 155, 1.0), 30, @selector(actionJailbreak), 1.0, 1.7);

    spiceLabel = [UILabel new];
    addLabel(spiceLabel, @"Spice", UICOLOR(110, 59, 38, 1.0), 24, 1.0, 0.4);

    titleLabel = [UILabel new];
    addLabel(titleLabel, @"First untether-upgradable iOS 11 jailbreak", UICOLOR(0, 0, 0, 1.0), 14, 1.0, 0.5);

    addTextView(self.textView, [self getInitialLogText], [UIColor whiteColor], 12.0, CGRectMake(50, 150, 300, 150), self.view.center);
}

// Jailbreak stuff

- (void)actionFailed
{
    self.textView.text = [self.textView.text stringByAppendingString:[NSString stringWithFormat:@"[*] Please add offsets for %@ on %@\n", deviceName(), [[UIDevice currentDevice] systemVersion]]];
}

- (void)actionJailbreak
{
    if (hasJailbroken) {
        respring();
        return;
    }

    jbButton.selected = NO;
    jbButton.highlighted = NO;
    jbButton.enabled = YES;
    [jbButton setTitle:@"Jailbreaking..." forState:UIControlStateNormal];

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^(void) {
        int ret = jailbreak(jailbreakFlags, self, &sendLog);
        NSLog(@"jailbreak ret: %d", ret);

        if (ret != 0) {
            NSLog(@"jailbreak failed");

            dispatch_async(dispatch_get_main_queue(), ^{
                [self exploitFailed];
            });

            return;
        }

        dispatch_async(dispatch_get_main_queue(), ^{
            [self exploitSucceeded];
        });
    });
}

- (void)exploitSucceeded
{
    jbButton.selected = NO;
    jbButton.highlighted = NO;
    jbButton.enabled = YES;
    hasJailbroken = true;

    [jbButton setTitle:@"Respring" forState:UIControlStateNormal];
}

- (void)exploitFailed
{
    jbButton.selected = NO;
    jbButton.highlighted = NO;
    jbButton.enabled = YES;

    [jbButton setTitle:@"Failed, try again?" forState:UIControlStateNormal];
}

@end
