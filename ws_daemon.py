import daemon

from ws_server import main

import logging

logger = logging.getLogger('__main__')
logger.setLevel(logging.DEBUG)

formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
sth = logging.StreamHandler()
sth.setLevel(logging.DEBUG)
sth.setFormatter(formatter)
logger.addHandler(sth)

lfh = logging.FileHandler('ws_server.log')
lfh.setFormatter(formatter)
logger.addHandler(lfh)

with daemon.DaemonContext(files_preserve = [lfh.stream,],):
    main()
