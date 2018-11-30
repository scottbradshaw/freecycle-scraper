import urllib3
import certifi
import re
import hashlib
import logging
import boto3
import json
from bs4 import BeautifulSoup
from datetime import datetime
from time import sleep
from botocore.exceptions import ClientError

# Set logger
FORMAT = '%(funcName)1s - # %(lineno)s - %(message)s'
logging.basicConfig(format=FORMAT)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Environment variables
ITEM_TABLE = 'freecycle-items'
S3_BUCKET = 'freecycle-scraping'
AWS_REGION = 'eu-west-1'
TABLE_ID = 'group_posts_table'
TABLE_URL = 'https://groups.freecycle.org/group/%s/posts/all?page=%d&resultsperpage=10'
MAX_NUMBER_TO_SCAN = 100
ITEM_KEYWORDS = ['table', 'tables', 'wood', 'dining', 'sofa', 'sofabed', 'jar', 'jars']

# Create aws connections
session = boto3.session.Session(profile_name='freecycle', region_name=AWS_REGION)
s3 = session.resource('s3')
ses = session.client('ses', region_name=AWS_REGION)

RECIPIENT = ses.list_verified_email_addresses()['VerifiedEmailAddresses'][0]
SENDER = "Freecycle Scraper <%s>" % RECIPIENT


def extract_table_from_html(table_url, table_id):
    http = urllib3.PoolManager(cert_reqs='CERT_REQUIRED', ca_certs=certifi.where())
    page = http.request('GET', table_url)

    soup = BeautifulSoup(page.data, 'html.parser')
    table = soup.find('table', {"id": table_id})

    return table


def string_found(string1, string2):
    return re.search(r"\b" + re.escape(string1) + r"\b", string2) != None


def send_email(item, freecycle_group):
    body_html = """<html>
    <head></head>
    <body>
      <h3>Freecycle match!</h3>
      <p>Item: %s</p>
      <p>Item url: %s</p>
    </body>
    </html>
                """ % (item['title'], item['url'])
    try:
        # Provide the contents of the email.
        response = ses.send_email(
            Destination={
                'ToAddresses': [
                    RECIPIENT,
                ],
            },
            Message={
                'Body': {
                    'Html': {
                        'Charset': "UTF-8",
                        'Data': body_html,
                    },
                },
                'Subject': {
                    'Charset': "UTF-8",
                    'Data': "Matched item: %s on Freecycle group %s" % (item['title'], freecycle_group),
                },
            },
            Source=SENDER
        )
    # Display an error if something goes wrong.
    except ClientError as e:
        logger.error(e.response['Error']['Message'])
        raise ClientError
    except Exception as error:
        raise Exception('Error: %s' % error)

    else:
        logger.info("Email sent! Message ID:"),
        logger.info(response['MessageId'])


def lambda_handler(event, context):

    logger.info('Event received: %s' % event)
    freecycle_group = event['FREECYCLE_GROUP']

    try:
        object = s3.Object(S3_BUCKET, freecycle_group)
        last_item = json.loads(object.get()['Body'].read().decode('utf-8'))
        last_item_hash = last_item['hash']
    except:
        logger.info('No stored file on S3')
        last_item = {}
        last_item_hash = ''

    # Initiate variables for loop
    freecycle_page = 1
    row_number = 0
    items = []
    table = extract_table_from_html(TABLE_URL % (freecycle_group, freecycle_page), TABLE_ID)
    running = True

    while running:

        try:
            if row_number == 10:
                freecycle_page += 1
                sleep(2)
                table = extract_table_from_html(TABLE_URL % (freecycle_group, freecycle_page), TABLE_ID)
                row_number = 0

            row = table.findAll('tr')[row_number]
            cells = row.findAll('td')
            cells = [str(x).replace('\n', '') for x in cells]
            datetime_regex = '\w{3}[ ]{1,}\w{3}[ ]{1,}\d{1,2}[ ]{1,}\d{2}:\d{2}:\d{2}[ ]{1,}\d{4}'
            first_cell = re.search(
                '.*<\/span> (OFFER|WANTED|TAKEN|RECEIVED)<\/span>.*<br\/> (' + datetime_regex + ')<br/>', cells[0])
            offer_or_wanted = first_cell.group(1)
            item_datetime = int(datetime.strptime(first_cell.group(2), '%a %b %d %H:%M:%S %Y').strftime('%Y%m%d%H%M%S'))

            second_cell = re.search('<a href="(.*)">(.*)<\/a>.*href', cells[1])
            item_url = second_cell.group(1)
            title = second_cell.group(2)
            item_hash = hashlib.md5((title + str(datetime)).encode()).hexdigest()

            item_details = dict([('datetime', item_datetime),
                                 ('title', title),
                                 ('url', item_url),
                                 ('hash', item_hash)])
            items.append(item_details)

            matching_item = any([string_found(keyword, item_details['title']) for keyword in ITEM_KEYWORDS])

            if item_hash == last_item_hash or len(items) == MAX_NUMBER_TO_SCAN:

                running = False
                object.put(Body=json.dumps(items[0], indent=4))

                logger.info('INFO: Previously scraped item reached')

            elif matching_item and offer_or_wanted == 'OFFER':
                logger.info('Matched item: %s' % item_details['title'])
                send_email(item_details, freecycle_group=freecycle_group)

            else:
                logger.info('Scraped %s' % item_details['title'])

        except ClientError as e:
            logger.error('Email error: %s' % e)

        except Exception as error:
            logger.error('Error: %s' % error)
            logger.error('Could not parse item %d on page %d' % (len(items), freecycle_page))

        finally:
            row_number += 1

    return 0


if __name__ == "__main__":
    lambda_handler({"FREECYCLE_GROUP":"LambethUK"}, {})
