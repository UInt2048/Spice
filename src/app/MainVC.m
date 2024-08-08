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

static void sendLog(void* controller, NSString* log)
{
    [(MainVC*)controller showLog:log];
}

@implementation MainVC

static UIButton* jbButton;
static UILabel *spiceLabel, *titleLabel;
static bool hasJailbroken = false;

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

- (void)loadView
{
    [super loadView];

    jbButton = [UIButton buttonWithType:UIButtonTypeSystem];
    jbButton.translatesAutoresizingMaskIntoConstraints = NO;
    [jbButton setTitle:@"Jailbreak" forState:UIControlStateNormal];
    [jbButton setTitleColor:UICOLOR(110, 59, 38, 1.0) forState:UIControlStateNormal];
    [jbButton setTitleColor:UICOLOR(35, 75, 155, 1.0) forState:UIControlStateHighlighted];
    [jbButton setBackgroundColor:UICOLOR(0, 0, 0, 0.0)];
    jbButton.titleLabel.font = [UIFont systemFontOfSize:30];
    [jbButton addTarget:self action:@selector(actionJailbreak) forControlEvents:UIControlEventTouchUpInside];

    spiceLabel = [UILabel new];
    spiceLabel.translatesAutoresizingMaskIntoConstraints = NO;
    spiceLabel.text = @"Spice";
    spiceLabel.textColor = UICOLOR(110, 59, 38, 1.0);
    [spiceLabel setBackgroundColor:UICOLOR(0, 0, 0, 0.0)];
    spiceLabel.font = [UIFont systemFontOfSize:24];

    titleLabel = [UILabel new];
    titleLabel.translatesAutoresizingMaskIntoConstraints = NO;
    titleLabel.text = @"First untether-upgradable iOS 11 jailbreak";
    [titleLabel setBackgroundColor:UICOLOR(0, 0, 0, 0.0)];
    titleLabel.font = [UIFont systemFontOfSize:14];

    self.textView.translatesAutoresizingMaskIntoConstraints = NO;
    self.textView.backgroundColor = UICOLOR(0, 0, 0, 0.3);
    self.textView.textColor = [UIColor whiteColor];

    offsets_t* off1 = malloc(sizeof(offsets_t));
    memset(off1, 0, sizeof(offsets_t));
    offset_struct_t* off2 = malloc(sizeof(offset_struct_t));
    memset(off2, 0, sizeof(offset_struct_t));

    if (populate_offsets(off1, off2)) {
        self.textView.text = [self.textView.text stringByAppendingString:[NSString stringWithFormat:@"[*] Using offsets for %@ on %@\n", deviceName(), [[UIDevice currentDevice] systemVersion]]];
        if (off1->flags & FLAG_VERIFIED) {
            self.textView.text = [self.textView.text stringByAppendingString:[NSString stringWithFormat:@"[*] Offsets verified for %@ on %@\n", deviceName(), [[UIDevice currentDevice] systemVersion]]];
        } else {
            self.textView.text = [self.textView.text stringByAppendingString:[NSString stringWithFormat:@"[*] Offsets unverified, please inform if it functions\n", deviceName(), [[UIDevice currentDevice] systemVersion]]];
        }
    } else {
        self.textView.text = [self.textView.text stringByAppendingString:[NSString stringWithFormat:@"[*] Offsets not found for %@ on %@\n", deviceName(), [[UIDevice currentDevice] systemVersion]]];
        [jbButton setTitle:@"No offsets" forState:UIControlStateNormal];
        [jbButton removeTarget:nil action:NULL forControlEvents:UIControlEventAllEvents];
        [jbButton addTarget:self action:@selector(actionFailed) forControlEvents:UIControlEventTouchUpInside];
    }

    self.textView.text = [self.textView.text stringByAppendingString:[NSString stringWithFormat:@"[*] Booted at %@\n", [[[NSISO8601DateFormatter alloc] init] stringFromDate:[NSDate dateWithTimeIntervalSince1970:bootsec()]]]];

    self.textView.editable = NO;
    self.textView.scrollEnabled = YES;
    self.textView.textContainerInset = UIEdgeInsetsMake(0, 15, 15, 15);
    self.textView.font = [UIFont fontWithName:@"Courier" size:(CGFloat)12.0];
    self.textView.frame = CGRectMake(50, 150, 300, 150);
    self.textView.center = self.view.center;
    [self.view addSubview:self.textView];

    [self.view addSubview:jbButton];
    [self.view addConstraint:[NSLayoutConstraint constraintWithItem:jbButton attribute:NSLayoutAttributeCenterX relatedBy:NSLayoutRelationEqual toItem:self.view attribute:NSLayoutAttributeCenterX multiplier:(CGFloat)1.0 constant:(CGFloat)0.0]];
    [self.view addConstraint:[NSLayoutConstraint constraintWithItem:jbButton attribute:NSLayoutAttributeCenterY relatedBy:NSLayoutRelationEqual toItem:self.view attribute:NSLayoutAttributeCenterY multiplier:(CGFloat)1.7 constant:(CGFloat)0.0]];

    [self.view addSubview:spiceLabel];
    [self.view addConstraint:[NSLayoutConstraint constraintWithItem:spiceLabel attribute:NSLayoutAttributeCenterX relatedBy:NSLayoutRelationEqual toItem:self.view attribute:NSLayoutAttributeCenterX multiplier:(CGFloat)1.0 constant:(CGFloat)0.0]];
    [self.view addConstraint:[NSLayoutConstraint constraintWithItem:spiceLabel attribute:NSLayoutAttributeCenterY relatedBy:NSLayoutRelationEqual toItem:self.view attribute:NSLayoutAttributeCenterY multiplier:(CGFloat)0.4 constant:(CGFloat)0.0]];

    [self.view addSubview:titleLabel];
    [self.view addConstraint:[NSLayoutConstraint constraintWithItem:titleLabel attribute:NSLayoutAttributeCenterX relatedBy:NSLayoutRelationEqual toItem:self.view attribute:NSLayoutAttributeCenterX multiplier:(CGFloat)1.0 constant:(CGFloat)0.0]];
    [self.view addConstraint:[NSLayoutConstraint constraintWithItem:titleLabel attribute:NSLayoutAttributeCenterY relatedBy:NSLayoutRelationEqual toItem:self.view attribute:NSLayoutAttributeCenterY multiplier:(CGFloat)0.5 constant:(CGFloat)0.0]];
}

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
        int ret = jailbreak(0, self, &sendLog);
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
