//
//  CocoaTagAppDelegate.m
//  CocoaTag
//
//  Created by Johnno Loggie on 20/11/2010.
//  Copyright 2010 __MyCompanyName__. All rights reserved.
//

#import "CocoaTagAppDelegate.h"

extern "C"
{
	#import "MifareFormat.h"
	#import "MifareURL.h"
}

#include <ndefmessage.h>

#include <QtCore/QLatin1String>

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

#define RECORD_HEADER_1_RECORD 0xd1
const uint8_t ndef_msg[15] = {
    RECORD_HEADER_1_RECORD, 0x01, 0x0b, 0x55, 0x01, 'j', 'o', 'h',
    'n', 'n', 'o', '.', 'c', 'o', 'm'
};


- (IBAction) writeURL: (id) sender
{
	
	NDEFMessage msg;
	msg.appendRecord(NDEFRecord::createUriRecord(    QString(QLatin1String("http://code.google.com/p/libndef")) ));
	msg.appendRecord(NDEFRecord::createTextRecord( QString(QLatin1String("Hello, world!")), QString(QLatin1String("en-US")) ));
	
	// ...and then we can serialize it and send everywhere.
	QByteArray output = msg.toByteArray();
	

	write_ndef( (const uint8_t*) output.data(),output.size());

	[self LogString: @"Wrote message\n"];
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
