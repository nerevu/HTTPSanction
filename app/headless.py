# -*- coding: utf-8 -*-
"""
    app.headless
    ~~~~~~~~~~~~

    Provides Chrome headless browser login functionality
"""
from functools import partial

import pygogo as gogo

from app.helpers import flask_formatter as formatter
from app.utils import fetch_value

from playwright.sync_api import sync_playwright


logger = gogo.Gogo(
    __name__, low_formatter=formatter, high_formatter=formatter, monolog=True
).logger
logger.propagate = False


def save_page(page, page_name, with_html=True):
    logger.debug(f"taking screenshot of {page_name}...")
    page.screenshot(path=f"screenshots/{page_name}.png", full_page=True)

    with open(f"{page_name}.html", "w") as f:
        print(f"saving html of {page_name}...")
        f.write(page.content())


def act_on_element(page, element, pos=0, debug=False):
    selector = element["selector"]
    el = page.locator(selector)
    el.wait_for()
    error_msg = None

    if not el:
        error_msg = "'{description}' selector '{selector}' not found!"
    elif element.get("content"):
        el.fill(element["content"])
    elif element.get("prompt"):
        content = fetch_value(element["description"])
        el.fill(content)
    elif "content" in element:
        error_msg = "No content supplied!"

    if debug:
        save_page(page, "{0} - {description}".format(pos + 1, **element))

    if (action := element.get("action")) == "submit":
        el.press("Enter")
    elif action:
        getattr(el, action)()

    if error_msg:
        raise AssertionError(error_msg.format(**element))


def _headless_auth(redirect_url, prefix, username=None, password=None, **kwargs):
    elements = kwargs.get("elements") or []
    debug = kwargs.get("debug")

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.goto(redirect_url)

        if debug:
            save_page(page, "0 - initial")

        act = partial(act_on_element, page, debug=debug)

        try:
            [act(element, pos) for pos, element in enumerate(elements)]
        except AssertionError as e:
            logger.error(e)
            browser.close()

        # TODO: Error if there are any button elements on the page
        browser.close()


def headless_auth(redirect_url, prefix, **kwargs):
    failed = True

    try:
        _headless_auth(redirect_url, prefix, **kwargs)
    except Exception as e:
        logger.error(e)
    else:
        failed = False
        logger.debug("Headless auth succeeded!")
    finally:
        if failed:
            logger.error("Headless auth failed!")

        return failed
