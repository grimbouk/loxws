import asyncio
import logging
import datetime
from loxws import LoxWS

timestamp = datetime.datetime.now().strftime("%Y-%m-%d-%H-%M")
logging.basicConfig(handlers=[logging.StreamHandler(),logging.FileHandler('loxws-{0}.log'.format(timestamp), 'w', 'utf-8')],level=logging.DEBUG,format='%(message)s')

_LOGGER = logging.getLogger(__name__)

async def main(loop):
    loxws = LoxWS(loop=loop)
    await loxws.connect()

if __name__ == '__main__':
    try:
        loop = asyncio.get_event_loop()
        loop.run_until_complete(main(loop))
        loop.run_forever()
    except KeyboardInterrupt:
        _LOGGER.info("Keyboard Interupt")
        pass
    finally:
        _LOGGER.info("Closing Loop")
    loop.close()