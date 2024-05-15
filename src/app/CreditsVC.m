#import "CreditsVC.h"

UILabel *creditLabel;

@implementation CreditsVC

- (id)init
{
    id ret = [super initWithNibName:nil bundle:nil];
    self.tabBarItem = [[UITabBarItem alloc] initWithTitle:@"Credits" image:nil tag:1];
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
    
    CAGradientLayer *gradient = [CAGradientLayer layer];
	gradient.frame = self.view.bounds;
	gradient.colors = @[(id)[UIColor colorWithRed:92.0/255.0 green:201.0/255.0 blue:59.0/255.0 alpha:1.0].CGColor,
		(id)[UIColor colorWithRed:42.0/255.0 green:100.0/255.0 blue:25.0/255.0 alpha:1.0].CGColor];
	[self.view.layer insertSublayer:gradient atIndex:0];
    
    creditLabel = [UILabel new];
    creditLabel.translatesAutoresizingMaskIntoConstraints = NO;
    creditLabel.numberOfLines = 0;
    creditLabel.text = @"\
- JakeBlair420 team for the actual jailbreak\n\
- Apple for XNU source and patching CVE-2012-3727 wrong\n\
- National Security Agency for Ghidra\n\
- planetbeing et al. for xpwntool\n\
- PrimePlatypus, LukeZGD, cxdxn1 for assistance\n\
- blacktop for the ipsw tool\n\
- Jonathan Levin for jtool";
    [creditLabel setBackgroundColor:[UIColor colorWithRed:1.00 green:0.00 blue:0.00 alpha:0.0]];
    creditLabel.font = [UIFont systemFontOfSize:14];
    
    [self.view addSubview:creditLabel];
    [self.view addConstraint:[NSLayoutConstraint constraintWithItem:creditLabel attribute:NSLayoutAttributeCenterX relatedBy:NSLayoutRelationEqual toItem:self.view attribute:NSLayoutAttributeCenterX multiplier:1.0 constant:0.0]];
    [self.view addConstraint:[NSLayoutConstraint constraintWithItem:creditLabel attribute:NSLayoutAttributeCenterY relatedBy:NSLayoutRelationEqual toItem:self.view attribute:NSLayoutAttributeCenterY multiplier:1.0 constant:0.0]];
}

@end
