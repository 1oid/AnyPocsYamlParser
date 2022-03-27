import os
from pprint import pprint
from optparse import OptionParser
from core.logger import getLogger
from template.options import Options
from template.template import Template
from template.model import Info
from template.request import Request
from template.runner import Runner


def scan_callback(template: Template, url: str):
    try:
        return {
                "severity": template.Info.SeverityHolder,
                "plugin": template.ID,
                "url": url,
                "name": template.Info.Name
            }
    except Exception as e:
        return None


if __name__ == '__main__':
    logger = getLogger()

    usage = '%prog -t http://localhost:8080'
    parser = OptionParser(usage=usage)
    parser.add_option("-t", "--target", dest="target", help="URL target", default=None)
    parser.add_option("", "--pocs", dest='pocs', help="pocs directory", default="vulns/")
    # parser.add_option("-a", "--all", dest='all', action="store_true", help="指定--all加载所有的poc")
    options, args = parser.parse_args()

    if not options.target:
        raise Exception("missing target")

    url = options.target
    pocs = options.pocs
    pocs = options.pocs if str(options.pocs).endswith("/") else pocs + "/"

    optionRunner = Options(
        url=url,
        templates=[pocs + x for x in os.listdir(pocs)]
    )

    logger.log(messages={
        "[INFO] ": "blue",
        "调用poc个数{}".format(len(optionRunner.Templates)): "white"
    })

    for item in Runner(optionRunner).run(scan_callback):
        pass



