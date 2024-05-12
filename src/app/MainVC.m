#include <shared/common.h>
#include <shared/jailbreak.h>
#include <shared/utils.h>
#include <shared/sbx.h>

#import <CoreFoundation/CoreFoundation.h>

#import "MainVC.h"

@implementation MainVC

UIButton *jbButton;
UILabel *titleLabel;
bool hasJailbroken = false;

- (id)init
{
    LOG("pullup");

    id ret = [super initWithNibName:nil bundle:nil];
    self.tabBarItem = [[UITabBarItem alloc] initWithTitle:@"Jailbreak" image:nil tag:1];
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
    
    titleLabel = [UILabel new];
    titleLabel.translatesAutoresizingMaskIntoConstraints = NO;
    titleLabel.text = @"First untether-upgradable iOS 11 jailbreak";
    [titleLabel setBackgroundColor:[UIColor colorWithRed:1.00 green:0.00 blue:0.00 alpha:0.0]];
    titleLabel.font = [UIFont systemFontOfSize:14];

    [self.view addSubview:jbButton];
    [self.view addConstraint:[NSLayoutConstraint constraintWithItem:jbButton attribute:NSLayoutAttributeCenterX relatedBy:NSLayoutRelationEqual toItem:self.view attribute:NSLayoutAttributeCenterX multiplier:1.0 constant:0.0]];
    [self.view addConstraint:[NSLayoutConstraint constraintWithItem:jbButton attribute:NSLayoutAttributeCenterY relatedBy:NSLayoutRelationEqual toItem:self.view attribute:NSLayoutAttributeCenterY multiplier:1.1 constant:0.0]];
    
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

    [jbButton setTitle:@"Jailbreaking..." forState:UIControlStateNormal];

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^(void) {
        int ret = jailbreak(0);
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
    hasJailbroken = true;

    [jbButton setTitle:@"Respring" forState:UIControlStateNormal];
}

- (void)exploitFailed
{
	[jbButton setTitle:@"Failed, try again?" forState:UIControlStateNormal];
}

@end
