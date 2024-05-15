#include <shared/common.h>
#include <shared/jailbreak.h>
#include <shared/utils.h>
#include <shared/sbx.h>

#import <CoreFoundation/CoreFoundation.h>

#import "MainVC.h"

void sendLog(void* controller, NSString* log) {
	[(MainVC*)controller showLog:log];
}

@implementation MainVC

UIButton *jbButton;
UILabel *spiceLabel, *titleLabel;
bool hasJailbroken = false;

-(void)showLog:(NSString *)log
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
    LOG("pullup");

    id ret = [super initWithNibName:nil bundle:nil];
    self.tabBarItem = [[UITabBarItem alloc] initWithTitle:@"Jailbreak" image:nil tag:1];
    self.textView = [[UITextView alloc] init];	
    return ret;
}

- (void)viewWillAppear:(BOOL)animated
{
	[super viewWillAppear:animated];
    CAGradientLayer *gradient = [CAGradientLayer layer];
	gradient.frame = self.view.bounds;
	gradient.colors = @[(id)[UIColor colorWithRed:92.0/255.0 green:201.0/255.0 blue:59.0/255.0 alpha:1.0].CGColor,
		(id)[UIColor colorWithRed:42.0/255.0 green:100.0/255.0 blue:25.0/255.0 alpha:1.0].CGColor];
	[self.view.layer insertSublayer:gradient atIndex:0];
}

- (void)loadView
{
    [super loadView];
    
    jbButton = [UIButton buttonWithType:UIButtonTypeSystem];
    jbButton.translatesAutoresizingMaskIntoConstraints = NO;
    [jbButton setTitle:@"Jailbreak" forState:UIControlStateNormal];
    [jbButton setTitleColor:[UIColor colorWithRed:110.0/255.0 green:59.0/255.0 blue:38.0/255.0 alpha:1.0] forState:UIControlStateNormal];
    [jbButton setTitleColor:[UIColor colorWithRed:35.0/255.0 green:75.0/255.0 blue:155.0/255.0 alpha:1.0] forState:UIControlStateHighlighted];
    [jbButton setBackgroundColor:[UIColor colorWithRed:1.00 green:0.00 blue:0.00 alpha:0.0]];
    jbButton.titleLabel.font = [UIFont systemFontOfSize:30];
    [jbButton addTarget:self action:@selector(actionJailbreak) forControlEvents:UIControlEventTouchUpInside];
    
    spiceLabel = [UILabel new];
    spiceLabel.translatesAutoresizingMaskIntoConstraints = NO;
    spiceLabel.text = @"Spice";
    spiceLabel.textColor = [UIColor colorWithRed:110.0/255.0 green:59.0/255.0 blue:38.0/255.0 alpha:1.0];
    [spiceLabel setBackgroundColor:[UIColor colorWithRed:1.00 green:0.00 blue:0.00 alpha:0.0]];
    spiceLabel.font = [UIFont systemFontOfSize:24];
    
    titleLabel = [UILabel new];
    titleLabel.translatesAutoresizingMaskIntoConstraints = NO;
    titleLabel.text = @"First untether-upgradable iOS 11 jailbreak";
    [titleLabel setBackgroundColor:[UIColor colorWithRed:1.00 green:0.00 blue:0.00 alpha:0.0]];
    titleLabel.font = [UIFont systemFontOfSize:14];
    
    self.textView.translatesAutoresizingMaskIntoConstraints = NO;
	self.textView.backgroundColor = [UIColor colorWithWhite:0.0 alpha:0.7];
	self.textView.textColor = [UIColor whiteColor];

#if N41_10_3_4
	self.textView.text = @"[*] Compiled for N41AP on iOS 10.3.4\n";
#elif N69_11_3
	self.textView.text = @"[*] Compiled for N69AP on iOS 11.3\n";
#elif N69_11_4
	self.textView.text = @"[*] Compiled for N69AP on iOS 11.4\n";
#elif N71_11_3_1
	self.textView.text = @"[*] Compiled for N71AP on iOS 11.3.1\n";
#elif J96_11_1_2
	self.textView.text = @"[*] Compiled for J96AP on iOS 11.1.2\n";
#elif J96_11_3_1
	self.textView.text = @"[*] Compiled for J96AP on iOS 11.3.1\n";
#else
	self.textView.text = @"[*] Compiled for unknown device\n";
#endif

	self.textView.editable = NO;
	self.textView.scrollEnabled = YES;
	self.textView.textContainerInset = UIEdgeInsetsMake(0, 15, 15, 15);
	self.textView.font = [UIFont fontWithName:@"Courier" size:12.0f];
	self.textView.frame = CGRectMake(50, 150, 300, 150);
	self.textView.center = self.view.center;
	[self.view addSubview:self.textView];

    [self.view addSubview:jbButton];
    [self.view addConstraint:[NSLayoutConstraint constraintWithItem:jbButton attribute:NSLayoutAttributeCenterX relatedBy:NSLayoutRelationEqual toItem:self.view attribute:NSLayoutAttributeCenterX multiplier:1.0 constant:0.0]];
    [self.view addConstraint:[NSLayoutConstraint constraintWithItem:jbButton attribute:NSLayoutAttributeCenterY relatedBy:NSLayoutRelationEqual toItem:self.view attribute:NSLayoutAttributeCenterY multiplier:1.7 constant:0.0]];

    [self.view addSubview:spiceLabel];
    [self.view addConstraint:[NSLayoutConstraint constraintWithItem:spiceLabel attribute:NSLayoutAttributeCenterX relatedBy:NSLayoutRelationEqual toItem:self.view attribute:NSLayoutAttributeCenterX multiplier:1.0 constant:0.0]];
    [self.view addConstraint:[NSLayoutConstraint constraintWithItem:spiceLabel attribute:NSLayoutAttributeCenterY relatedBy:NSLayoutRelationEqual toItem:self.view attribute:NSLayoutAttributeCenterY multiplier:0.4 constant:0.0]];
    
    [self.view addSubview:titleLabel];
    [self.view addConstraint:[NSLayoutConstraint constraintWithItem:titleLabel attribute:NSLayoutAttributeCenterX relatedBy:NSLayoutRelationEqual toItem:self.view attribute:NSLayoutAttributeCenterX multiplier:1.0 constant:0.0]];
    [self.view addConstraint:[NSLayoutConstraint constraintWithItem:titleLabel attribute:NSLayoutAttributeCenterY relatedBy:NSLayoutRelationEqual toItem:self.view attribute:NSLayoutAttributeCenterY multiplier:0.5 constant:0.0]];
}

- (void)actionJailbreak
{
    if (hasJailbroken)
    {
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
