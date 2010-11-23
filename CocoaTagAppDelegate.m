//
//  CocoaTagAppDelegate.m
//  CocoaTag
//
//  Created by Johnno Loggie on 20/11/2010.
//  Copyright 2010 __MyCompanyName__. All rights reserved.
//

#import "CocoaTagAppDelegate.h"
#import "MifareFormat.h"
#import "MifareURL.h"


@implementation CocoaTagAppDelegate

@synthesize window;

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification {
	// Insert code here to initialize your application 
}

- (IBAction) formatTag: (id) sender
{
	format_tag();
	[self LogString: @"\n"];
}

- (IBAction) writeURL: (id) sender
{
	write_url();
	[self LogString: @"\n"];
}


- (void) LogString: (NSString*) myText;
{
    NSRange endRange;
    endRange.location = txtLog.textStorage.length;
    endRange.length = 0;
    [txtLog replaceCharactersInRange:endRange withString:myText];
    endRange.length = myText.length;
    [txtLog scrollRangeToVisible:endRange];
}



@end
