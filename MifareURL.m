/*
 *  MifareURL.c
 *  CocoaTag
 *
 *  Created by Johnno Loggie on 23/11/2010.
 *  Copyright 2010 __MyCompanyName__. All rights reserved.
 *
 */

#import "LibFreefare.h"
#import "MifareURL.h"


extern MifareClassicKey default_keys[6*8];

struct mifare_classic_key_and_type {
    MifareClassicKey key;
    MifareClassicKeyType type;
};

const MifareClassicKey default_keyb = {
    0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7
};



int
search_sector_key (MifareTag tag, MifareClassicSectorNumber sector, MifareClassicKey *key, MifareClassicKeyType *key_type)
{
    MifareClassicBlockNumber block = mifare_classic_sector_last_block (sector);
	
    /*
     * FIXME: We should not assume that if we have full access to trailer block
     *        we also have a full access to data blocks.
     */
    mifare_classic_disconnect (tag);
    for (size_t i = 0; i < (sizeof (default_keys) / sizeof (MifareClassicKey)); i++) {
		if ((0 == mifare_classic_connect (tag)) && (0 == mifare_classic_authenticate (tag, block, default_keys[i], MFC_KEY_A))) {
			if ((1 == mifare_classic_get_trailer_block_permission (tag, block, MCAB_WRITE_KEYA, MFC_KEY_A)) &&
				(1 == mifare_classic_get_trailer_block_permission (tag, block, MCAB_WRITE_ACCESS_BITS, MFC_KEY_A)) &&
				(1 == mifare_classic_get_trailer_block_permission (tag, block, MCAB_WRITE_KEYB, MFC_KEY_A))) {
				memcpy (key, &default_keys[i], sizeof (MifareClassicKey));
				*key_type = MFC_KEY_A;
				return 1;
			}
		}
		mifare_classic_disconnect (tag);
		
		if ((0 == mifare_classic_connect (tag)) && (0 == mifare_classic_authenticate (tag, block, default_keys[i], MFC_KEY_B))) {
			if ((1 == mifare_classic_get_trailer_block_permission (tag, block, MCAB_WRITE_KEYA, MFC_KEY_B)) &&
				(1 == mifare_classic_get_trailer_block_permission (tag, block, MCAB_WRITE_ACCESS_BITS, MFC_KEY_B)) &&
				(1 == mifare_classic_get_trailer_block_permission (tag, block, MCAB_WRITE_KEYB, MFC_KEY_B))) {
				memcpy (key, &default_keys[i], sizeof (MifareClassicKey));
				*key_type = MFC_KEY_B;
				return 1;
			}
		}
		mifare_classic_disconnect (tag);
    }
	
    warnx ("No known authentication key for sector 0x%02x\n", sector);
    return 0;
}

int
fix_mad_trailer_block (nfc_device_t *device, MifareTag tag, MifareClassicSectorNumber sector, MifareClassicKey key, MifareClassicKeyType key_type)
{
    MifareClassicBlock block;
    mifare_classic_trailer_block (&block, mad_public_key_a, 0x0, 0x1, 0x1, 0x6, 0x00, default_keyb);
    if (mifare_classic_authenticate (tag, mifare_classic_sector_last_block (sector), key, key_type) < 0) {
		nfc_perror (device, "fix_mad_trailer_block mifare_classic_authenticate");
		return -1;
    }
    if (mifare_classic_write (tag, mifare_classic_sector_last_block (sector), block) < 0) {
		nfc_perror (device, "mifare_classic_write");
		return -1;
    }
    return 0;
}

void write_ndef(const uint8_t* ndef_msg,size_t ndef_msg_size)
{
    int error = 0;
    nfc_device_t *device = NULL;
    MifareTag *tags = NULL;
    Mad mad;
    MifareClassicKey transport_key = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	

    struct mifare_classic_key_and_type *card_write_keys;
    if (!(card_write_keys = malloc (40 * sizeof (*card_write_keys)))) {
		err (EXIT_FAILURE, "malloc");
    }
	
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
			errx (EXIT_FAILURE, "Error listing MIFARE classic tag.");
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
			
			printf ("Found %s with UID %s. Write NDEF [yN] ", freefare_get_tag_friendly_name (tags[i]), tag_uid);
			bool write_ndef = YES;
			
			for (int n = 0; n < 40; n++) {
				memcpy(card_write_keys[n].key, transport_key, sizeof (transport_key));
				card_write_keys[n].type = MFC_KEY_A;
			}
			
			if (write_ndef) {
				switch (freefare_get_tag_type (tags[i])) {
					case CLASSIC_4K:
						if (!search_sector_key (tags[i], 0x10, &(card_write_keys[0x10].key), &(card_write_keys[0x10].type))) {
							error = 1;
							goto error;
						}
						/* fallthrough */
					case CLASSIC_1K:
						if (!search_sector_key (tags[i], 0x00, &(card_write_keys[0x00].key), &(card_write_keys[0x00].type))) {
							error = 1;
							goto error;
						}
						break;
					default:
						/* Keep compiler quiet */
						break;
				}
				
				if (!error) {
					/* Ensure the auth key is always a B one. If not, change it! */
					switch (freefare_get_tag_type (tags[i])) {
						case CLASSIC_4K:
							if (card_write_keys[0x10].type != MFC_KEY_B) {
								if( 0 != fix_mad_trailer_block (device, tags[i], 0x10, card_write_keys[0x10].key, card_write_keys[0x10].type)) {
									error = 1;
									goto error;
								}
								memcpy (&(card_write_keys[0x10].key), &default_keyb, sizeof (MifareClassicKey));
								card_write_keys[0x10].type = MFC_KEY_B;
							}
							/* fallthrough */
						case CLASSIC_1K:
							if (card_write_keys[0x00].type != MFC_KEY_B) {
								if( 0 != fix_mad_trailer_block (device, tags[i], 0x00, card_write_keys[0x00].key, card_write_keys[0x00].type)) {
									error = 1;
									goto error;
								}
								memcpy (&(card_write_keys[0x00].key), &default_keyb, sizeof (MifareClassicKey));
								card_write_keys[0x00].type = MFC_KEY_B;
							}
							break;
						default:
							/* Keep compiler quiet */
							break;
					}
				}
				
				size_t encoded_size;
				uint8_t *tlv_data = tlv_encode (3, ndef_msg, ndef_msg_size, &encoded_size);
				
				/*
				 * At his point, we should have collected all information needed to
				 * succeed.
				 */
				
				// If the card already has a MAD, load it.
				if ((mad = mad_read (tags[i]))) {
					// If our application already exists, erase it.
					MifareClassicSectorNumber *sectors, *p;
					sectors = p = mifare_application_find (mad, mad_nfcforum_aid);
					if (sectors) {
						while (*p) {
							if (mifare_classic_authenticate (tags[i], mifare_classic_sector_last_block(*p), default_keyb, MFC_KEY_B) < 0) {
								nfc_perror (device, "mifare_classic_authenticate");
								error = 1;
								goto error;
							}
							if (mifare_classic_format_sector (tags[i], *p) < 0) {
								nfc_perror (device, "mifare_classic_format_sector");
								error = 1;
								goto error;
							}
							p++;
						}
					}
					free (sectors);
					mifare_application_free (mad, mad_nfcforum_aid);
				} else {
					
					// Create a MAD and mark unaccessible sectors in the card
					if (!(mad = mad_new ((freefare_get_tag_type (tags[i]) == CLASSIC_4K) ? 2 : 1))) {
						perror ("mad_new");
						error = 1;
						goto error;
					}
					
					MifareClassicSectorNumber max_s;
					switch (freefare_get_tag_type (tags[i])) {
						case CLASSIC_1K:
							max_s = 15;
							break;
						case CLASSIC_4K:
							max_s = 39;
							break;
						default:
							/* Keep compiler quiet */
							break;
					}
					
					// Mark unusable sectors as so
					for (size_t s = max_s; s; s--) {
						if (s == 0x10) continue;
						if (!search_sector_key (tags[i], s, &(card_write_keys[s].key), &(card_write_keys[s].type))) {
							mad_set_aid (mad, s, mad_defect_aid);
						} else if ((memcmp (card_write_keys[s].key, transport_key, sizeof (transport_key)) != 0) &&
								   (card_write_keys[s].type != MFC_KEY_A)) {
							// Revert to transport configuration
							if (mifare_classic_format_sector (tags[i], s) < 0) {
								nfc_perror (device, "mifare_classic_format_sector");
								error = 1;
								goto error;
							}
						}
					}
				}
				
				MifareClassicSectorNumber *sectors = mifare_application_alloc (mad, mad_nfcforum_aid, encoded_size);
				if (!sectors) {
					nfc_perror (device, "mifare_application_alloc");
					error = EXIT_FAILURE;
					goto error;
				}
				
				if (mad_write (tags[i], mad, card_write_keys[0x00].key, card_write_keys[0x10].key) < 0) {
					nfc_perror (device, "mad_write");
					error = EXIT_FAILURE;
					goto error;
				}
				
				int s = 0;
				while (sectors[s]) {
					MifareClassicBlockNumber block = mifare_classic_sector_last_block (sectors[s]);
					MifareClassicBlock block_data;
					mifare_classic_trailer_block (&block_data, mifare_classic_nfcforum_public_key_a, 0x0, 0x0, 0x0, 0x6, 0x40, default_keyb);
					if (mifare_classic_authenticate (tags[i], block, card_write_keys[sectors[s]].key, card_write_keys[sectors[s]].type) < 0) {
						nfc_perror (device, "mifare_classic_authenticate");
						error = EXIT_FAILURE;
						goto error;
					}
					if (mifare_classic_write (tags[i], block, block_data) < 0) {
						nfc_perror (device, "mifare_classic_write");
						error = EXIT_FAILURE;
						goto error;
					}
					s++;
				}
				
				if ((ssize_t) encoded_size != mifare_application_write (tags[i], mad, mad_nfcforum_aid, tlv_data, encoded_size, default_keyb, MCAB_WRITE_KEYB)) {
					nfc_perror (device, "mifare_application_write");
					error = EXIT_FAILURE;
					goto error;
				}
				
				free (sectors);
				
				free (tlv_data);
				
				free (mad);
			}
			
		error:
			free (tag_uid);
		}
		
		freefare_free_tags (tags);
		nfc_disconnect (device);
    }
	
    free (card_write_keys);
}


