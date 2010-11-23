/*
 *  MifareFormat.c
 *  CocoaTag
 *
 *  Created by Johnno Loggie on 20/11/2010.
 *  Copyright 2010 __MyCompanyName__. All rights reserved.
 *
 */
#import "CocoaTagAppDelegate.h"
#import "LibFreefare.h"
#import "MifareFormat.h"

MifareClassicKey default_keys[] = {
    { 0xff,0xff,0xff,0xff,0xff,0xff },
    { 0xd3,0xf7,0xd3,0xf7,0xd3,0xf7 },
    { 0xa0,0xa1,0xa2,0xa3,0xa4,0xa5 },
    { 0xb0,0xb1,0xb2,0xb3,0xb4,0xb5 },
    { 0x4d,0x3a,0x99,0xc3,0x51,0xdd },
    { 0x1a,0x98,0x2c,0x7e,0x45,0x9a },
    { 0xaa,0xbb,0xcc,0xdd,0xee,0xff },
    { 0x00,0x00,0x00,0x00,0x00,0x00 }
};
int		 format_mifare_classic_1k (MifareTag tag);
int		 format_mifare_classic_4k (MifareTag tag);
int		 try_format_sector (MifareTag tag, MifareClassicSectorNumber sector);

struct {
    bool fast;
    bool interactive;
} format_options = {
    .fast        = false,
    .interactive = true
};

static int at_block = 0;
static int mod_block = 10;

void
display_progress ()
{
    at_block++;
    if (0 == (at_block % mod_block)) {
		printf ("%d", at_block);
		fflush (stdout);
    } else {
		printf (".");
		fflush (stdout);
    }
}

int
format_mifare_classic_1k (MifareTag tag)
{
    LogString(@"Formatting %d sectors",16);
    for (int sector = 0; sector < 16; sector++) {
		if (!try_format_sector (tag, sector))
			return 0;
    }
	LogString(@"] done.");
    return 1;
}

int
format_mifare_classic_4k (MifareTag tag)
{
	LogString(@"Formatting %d sectors",32 + 8);
    for (int sector = 0; sector < (32 + 8); sector++) {
		if (!try_format_sector (tag, sector))
			return 0;
    }
	LogString(@"] done.");
    return 1;
}

int
try_format_sector (MifareTag tag, MifareClassicSectorNumber sector)
{
    display_progress ();
    for (size_t i = 0; i < (sizeof (default_keys) / sizeof (MifareClassicKey)); i++) {
		MifareClassicBlockNumber block = mifare_classic_sector_last_block (sector);
		if ((0 == mifare_classic_connect (tag)) && (0 == mifare_classic_authenticate (tag, block, default_keys[i], MFC_KEY_A))) {
			if (0 == mifare_classic_format_sector (tag, sector)) {
				mifare_classic_disconnect (tag);
				return 1;
			} else if (EIO == errno) {
				err (EXIT_FAILURE, "sector %d", sector);
			}
			mifare_classic_disconnect (tag);
		}
		
		if ((0 == mifare_classic_connect (tag)) && (0 == mifare_classic_authenticate (tag, block, default_keys[i], MFC_KEY_B))) {
			if (0 == mifare_classic_format_sector (tag, sector)) {
				mifare_classic_disconnect (tag);
				return 1;
			} else if (EIO == errno) {
				err (EXIT_FAILURE, "sector %d", sector);
			}
			mifare_classic_disconnect (tag);
		}
    }
	
    warnx ("No known authentication key for sector %d", sector);
    return 0;
}


void format_tag()
{
	int ch;
    int error = EXIT_SUCCESS;
    nfc_device_t *device = NULL;
    MifareTag *tags = NULL;
	
	format_options.fast = true;
	format_options.interactive = false;
	
    nfc_device_desc_t devices[8];
    size_t device_count;
	
    nfc_list_devices (devices, 8, &device_count);
    if (!device_count)
		errx (EXIT_FAILURE, "No NFC device found.");
	
    for (size_t d = 0; d < device_count; d++) {
		device = nfc_connect (&(devices[d]));
		if (!device) {
			warnx ("nfc_connect() failed.");
			error = EXIT_FAILURE;
			continue;
		}
		
		tags = freefare_get_tags (device);
		if (!tags) {
			nfc_disconnect (device);
			errx (EXIT_FAILURE, "Error listing Mifare Classic tag.");
		}
		
		for (int i = 0; (!error) && tags[i]; i++) {
			switch (freefare_get_tag_type (tags[i])) {
				case CLASSIC_1K:
				case CLASSIC_4K:
					break;
				default:
					continue;
			}
			
			char *tag_uid = freefare_get_tag_uid (tags[i]);
			char buffer[BUFSIZ];
			
			
			NSString* strTagType = [NSString stringWithCString: freefare_get_tag_friendly_name (tags[i])];
			NSString* strTagUid  = [NSString stringWithCString: tag_uid];
			LogString (@"Found %@ with UID %@",strTagType,strTagUid);
			
			bool format = true;
			if (format_options.interactive) {
				printf ("Format [yN] ");
				fgets (buffer, BUFSIZ, stdin);
				format = ((buffer[0] == 'y') || (buffer[0] == 'Y'));
			} else {
				printf ("\n");
			}
			
			if (format) {
				enum mifare_tag_type tt = freefare_get_tag_type (tags[i]);
				at_block = 0;
				
				if (format_options.fast) {
					printf ("Formatting %d sectors", (tt == CLASSIC_1K) ? 1 : 2);
					if (!try_format_sector (tags[i], 0x00))
						break;
					
					if (tt == CLASSIC_4K)
						if (!try_format_sector (tags[i], 0x10))
							break;
					
					printf (@"] done.");
					continue;
				}
				switch (tt) {
					case CLASSIC_1K:
						mod_block = 4;
						if (!format_mifare_classic_1k (tags[i]))
							error = 1;
						break;
					case CLASSIC_4K:
						mod_block = 10;
						if (!format_mifare_classic_4k (tags[i]))
							error = 1;
						break;
					default:
						/* Keep compiler quiet */
						break;
				}
			}
			
			free (tag_uid);
		}
		
		freefare_free_tags (tags);
		nfc_disconnect (device);
    }
}
