#import "CreditsVC.h"

static UILabel* creditLabel;

#define UICOLOR(r, g, b, a) [UIColor colorWithRed:(CGFloat)(r / 255.0) green:(CGFloat)(g / 255.0) blue:(CGFloat)(b / 255.0) alpha:(CGFloat)a]
#define CGCOLOR(r, g, b, a) (id) UICOLOR(r, g, b, a).CGColor

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
    CAGradientLayer* gradient = [CAGradientLayer layer];
    gradient.frame = self.view.bounds;
    gradient.colors = @[ CGCOLOR(92, 201, 59, 1.0), CGCOLOR(42, 100, 25, 1.0) ];
    [self.view.layer insertSublayer:gradient atIndex:0];
}

- (void)loadView
{
    [super loadView];

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
    [creditLabel setBackgroundColor:UICOLOR(0, 0, 0, 0.0)];
    creditLabel.font = [UIFont systemFontOfSize:14];

    [self.view addSubview:creditLabel];
    [self.view addConstraint:[NSLayoutConstraint constraintWithItem:creditLabel attribute:NSLayoutAttributeCenterX relatedBy:NSLayoutRelationEqual toItem:self.view attribute:NSLayoutAttributeCenterX multiplier:1.0 constant:0.0]];
    [self.view addConstraint:[NSLayoutConstraint constraintWithItem:creditLabel attribute:NSLayoutAttributeCenterY relatedBy:NSLayoutRelationEqual toItem:self.view attribute:NSLayoutAttributeCenterY multiplier:1.0 constant:0.0]];
}

@end
