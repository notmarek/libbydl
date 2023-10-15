import io
import json
import sys
from time import time

import click
import requests
from colorama import Fore, init
from loguru import logger
from tabulate import tabulate

from LibbyDL.DeDRM.dedrm_acsm import dedrm

ENDPOINT = "https://sentry-read.svc.overdrive.com"
THUNDER_ENDPOINT = "https://thunder.api.overdrive.com"
USER_AGENT = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) (Dewey; V22; iOS; 6.3.0-160)"


class LibbyClient:
    def __init__(self):
        self.identity = None
        self.data = None
        self.r = requests.Session()
        self.r.headers.update({"User-Agent": USER_AGENT})
        return

    def acquire_identity(self):
        res = self.r.post(f"{ENDPOINT}/chip?client=dewey",
                          headers={} if self.identity is None else {"Authorization": f"Bearer {self.identity}"})
        self.identity = res.json()["identity"]

    def clone(self, code):
        self.acquire_identity()
        res = self.r.post(f"{ENDPOINT}/chip/clone/code", json={"code": f"{code}"},
                          headers={"authorization": f"Bearer {self.identity}"})
        return res

    def sync(self):
        self.acquire_identity()
        res = self.r.get(f"{ENDPOINT}/chip/sync", headers={"authorization": f"Bearer {self.identity}"})
        self.data = res.json()
        logger.debug(res.json())
        return res

    def fulfill_book(self, book_id):
        loan = [x for x in self.data["loans"] if x["id"] == f"{book_id}"][0]
        res = self.r.get(f"{ENDPOINT}/card/{loan['cardId']}/loan/{book_id}/fulfill/ebook-epub-adobe",
                         headers={"authorization": f"Bearer {self.identity}"})
        return res.content

    def return_book(self, book_id):
        try:
            loan = [x for x in self.data["loans"] if x["id"] == f"{book_id}"][0]
            logger.info(f"Returning \"{loan['title']}\"")
        except IndexError:
            return False
        res = self.r.delete(f"{ENDPOINT}/card/{loan['cardId']}/loan/{book_id}",
                            headers={"authorization": f"Bearer {self.identity}"})
        if res.ok:
            self.data["loans"].remove(loan)
        return res.ok

    def unhold_book(self, book_id):
        try:
            hold = [x for x in self.data["holds"] if x["id"] == f"{book_id}"][0]
        except IndexError:
            return False
        res = self.r.delete(f"{ENDPOINT}/card/{hold['cardId']}/hold/{book_id}",
                            headers={"authorization": f"Bearer {self.identity}"})
        if res.ok:
            self.data["loans"].remove(hold)
        return res.ok

    def suspend_hold(self, book_id, days):
        try:
            hold = [x for x in self.data["holds"] if x["id"] == f"{book_id}"][0]
        except IndexError:
            return False
        res = self.r.put(f"{ENDPOINT}/card/{hold['cardId']}/hold/{book_id}",
                         json={"days_to_suspend": days},
                         headers={"authorization": f"Bearer {self.identity}"})
        return res.ok

    def export_code(self):
        res = self.r.get(f"{ENDPOINT}/chip/clone/code", headers={"Authorization": f"Bearer {self.identity}"})
        return res.json()

    def borrow_book(self, book_id):
        # We don't need to borrow again if there's already an active loan with the same id
        loaned = [x for x in self.data["loans"] if str(x["id"]) == str(book_id)]
        if len(loaned) > 0:
            logger.info(f"\"{loaned[0]['title']}\" is already in your loans.")
            return loaned[0]
        card = None
        for lib in self.data["cards"]:
            avail = self.r.post(
                f"{THUNDER_ENDPOINT}/v2/libraries/{lib['advantageKey']}/media/availability?x-client-id=dewey",
                json={"ids": [f"{book_id}"]}).json()
            if avail["items"][0] is not None and avail["items"][0]["isAvailable"]:
                logger.debug(json.dumps(avail['items'][0], indent=4))
                logger.info(f'Borrowing book with id "{book_id}" from "{lib["library"]["name"]}"')
                card = lib
                break
        if card is None:
            return False

        res = self.r.post(f"{ENDPOINT}/card/{card['cardId']}/loan/{book_id}",
                          json={"period": card["lendingPeriods"]["book"]["preference"][0],
                                "units": card["lendingPeriods"]["book"]["preference"][1], "lucky_day": None,
                                "title_format": "ebook", "reporting_context": {
                                  "listSourceName": "search",
                                  "listSourceId": "",
                                  "listPath": f"library/{card['advantageKey']}/search/query-",
                                  "clientName": "Dewey",
                                  "clientVersion": "16.0.1",
                                  "environment": "charlie"
                              }}, headers={"authorization": f"Bearer {self.identity}"})
        if res.ok:
            self.data["loans"].append(res.json())
        return res.ok

    def hold_book(self, book_id):
        # We don't need to hold again if there's already an active hold with the same id
        holding = [x for x in self.data["holds"] if str(x["id"]) == str(book_id)]
        if len(holding) > 0:
            return holding[0]

        card = None
        for lib in self.data["cards"]:
            avail = self.r.post(
                f"{THUNDER_ENDPOINT}/v2/libraries/{lib['advantageKey']}/media/availability?x-client-id=dewey",
                json={"ids": [f"{book_id}"]}).json()
            if avail["items"][0] is not None and avail["items"][0]["isHoldable"]:
                card = lib
                break
        if card is None:
            return False

        res = self.r.post(f"{ENDPOINT}/card/{card['cardId']}/hold/{book_id}",
                          json={"days_to_suspend": 0,
                                "email_address": card["emailAddress"] if card["emailAddress"] is not None else "",
                                "title_format": "ebook", "reporting_context": {
                                  "listSourceName": "search",
                                  "listSourceId": "",
                                  "listPath": f"library/{card['advantageKey']}/search/query-",
                                  "clientName": "Dewey",
                                  "clientVersion": "16.0.1",
                                  "environment": "charlie"
                              }}, headers={"authorization": f"Bearer {self.identity}"})
        if res.ok:
            self.data["holds"].append(res.json())
        return res.ok

    def search(self, query):
        items = []
        # for card in self.data["cards"]:
        res = self.r.get(
            f"{THUNDER_ENDPOINT}/v2/libraries/{self.data['cards'][0]['advantageKey']}/media?query={query}&format=ebook-overdrive,ebook-media-do,ebook-overdrive-provisional&perPage=50&page=1&x-client-id=dewey")
        data = res.json()
        items = data["items"]

        ids = [x["id"] for x in items]
        result = {}
        for x in self.data["cards"]:
            lib = x["advantageKey"]
            r = self.r.post(f"{THUNDER_ENDPOINT}/v2/libraries/{lib}/media/availability?x-client-id=dewey",
                            json={"ids": ids})
            d = r.json()["items"]
            for i, x in enumerate(items):
                if d[i] is not None:
                    if not x["id"] in result:
                        result[x["id"]] = {"id": x["id"], "title": x["title"], "author": x["firstCreatorName"],
                                           "libraries": {}}
                    result[x["id"]]["libraries"].update({f"{lib}": {"available": d[i]["isAvailable"],
                                                                    "holdable": d[i]["isHoldable"],
                                                                    "estimatedWaitDays": d[i][
                                                                        "estimatedWaitDays"] if "estimatedWaitDays" in
                                                                                                d[i] else None}})

        return result.values()


def download_book(book_id, client, return_b=True, borrow_b=True):
    if borrow_b:
        logger.info("Borrowing book.")
        client.borrow_book(book_id)
    logger.info("Fulfilling book")
    acsm = io.BytesIO(client.fulfill_book(book_id))
    logger.info("Decrypting book")
    dedrm(acsm, "./books/")
    if return_b:
        client.return_book(book_id)


def tablify(table):
    return tabulate(table, headers="firstrow", tablefmt="github")


@click.group()
@click.option('--token', envvar="LIBBY_IDENTITY", default=None)
@click.option("--debug", default=False, is_flag=True)
@click.option("--quiet", default=False, is_flag=True)
@click.pass_context
def cli(ctx, token, debug, quiet):
    logger.remove(0)
    logger.add(sys.stdout, level="INFO" if not debug else "DEBUG" if not quiet else "ERROR")
    init(autoreset=True)
    if ctx.invoked_subcommand == "clone":
        return
    ctx.ensure_object(LibbyClient)
    if token is None:
        with open("./.libby_identity", "r") as f:
            token = f.read()

    c = LibbyClient()
    if token is not None:
        c.identity = token
    else:
        raise click.UsageError("You need to provide an identity token or sync with your Libby app.")
    c.sync()
    ctx.obj = c


@cli.command()
@click.argument("clone_code")
def clone(clone_code):
    c = LibbyClient()
    c.clone(clone_code)
    c.acquire_identity()
    c.sync()
    with open(".libby_identity", "w") as f:
        f.write(c.identity)
    click.echo("Identity cloned and saved.")


@cli.command()
@click.pass_context
def export_code(ctx):
    res = ctx.obj.export_code()
    time_left = res["expiry"] - time()
    code = str(res['code'])
    code = code[:4] + " " + code[4:]
    logger.info(f"Code: {code} - valid for {int(time_left)}s")


@cli.command()
@click.option("--no-return", type=bool, default=False, is_flag=True)
@click.argument("book_id")
@click.pass_context
def download(ctx, book_id, no_return):
    download_book(book_id, ctx.obj, not no_return)


@cli.command()
@click.argument("book_ids")
@click.pass_context
def borrow(ctx, book_ids):
    for book_id in book_ids.split(","):
        ctx.obj.borrow_book(book_id)


@cli.command(name="return")
@click.argument("book_ids")
@click.pass_context
def return_book(ctx, book_ids):
    for book_id in book_ids:
        ctx.obj.return_book(book_id)


@cli.command(name="hold")
@click.argument("book_id")
@click.pass_context
def hold_book(ctx, book_id):
    ctx.obj.hold_book(book_id)


@cli.command(name="unhold")
@click.argument("book_id")
@click.pass_context
def unhold_book(ctx, book_id):
    ctx.obj.unhold_book(book_id)


@cli.command(name="suspend-hold")
@click.argument("book_id")
@click.argument("days", type=int)
@click.pass_context
def suspend_hold(ctx, book_id, days):
    ctx.obj.suspend_hold(book_id, days)


@cli.command()
@click.pass_context
def loans(ctx):
    table = [["ID", "Author", "Title", "Expiration Date"]]
    for x in ctx.obj.data["loans"]:
        table.append(
            [x["id"], x['firstCreatorName'] if "firstCreatorName" in x else "???", x["title"], x['expireDate']])
        logger.debug(
            f"{x['id']} - {x['firstCreatorName'] if 'firstCreatorName' in x else '???'} - {x['title']} - Expires: {x['expireDate']}")
    click.echo(tablify(table))


@cli.command()
@click.option("--no-return", type=bool, default=False, is_flag=True)
@click.pass_context
def download_loans(ctx, no_return):
    logger.debug(f"Going to download {len(ctx.obj.data['loans'])} books")
    logger.debug(json.dumps(ctx.obj.data["loans"], indent=4))
    for book in ctx.obj.data["loans"]:
        logger.debug(f"Downloading: {book['id']}")
        download_book(book["id"], ctx.obj, False, False)
    if not no_return:
        for x in [x['id'] for x in ctx.obj.data["loans"]]:
            ctx.obj.return_book(x)


@cli.command()
@click.pass_context
def holds(ctx):
    table = [["ID", "Author", "Title", "Estimated wait time"]]
    for x in ctx.obj.data["holds"]:
        wait_time = int(x["estimatedWaitDays"])
        color = Fore.GREEN if wait_time < 7 else (Fore.YELLOW if wait_time < 30 else Fore.RED)
        table.append([x["id"], x["firstCreatorName"], x["title"], f'{color}{x["estimatedWaitDays"]} days{Fore.RESET}'])
        logger.debug(
            f"{x['id']} - {x['firstCreatorName']} - {x['title']} - Estimated Wait: {x['estimatedWaitDays']} days")
    click.echo(tablify(table))


@cli.command()
@click.argument("query", required=True)
@click.pass_context
def search(ctx, query):
    table = [['ID', "Author", "Title", "Availability"]]
    for book in ctx.obj.search(query):
        available = [x for x in book['libraries'] if book['libraries'][x]['available']]
        if len(available) == 0:
            wait_time = [book["libraries"][x] for x in book["libraries"]]
            wait_time.sort(key=lambda x: x["estimatedWaitDays"] if x["estimatedWaitDays"] else 999)
            if wait_time[0]["holdable"]:
                wait_time = wait_time[0]["estimatedWaitDays"] if wait_time[0]["estimatedWaitDays"] else "?"
                availability = Fore.YELLOW + f"Holdable - {wait_time} days"
            else:
                availability = Fore.RED + 'Unavailable'
        else:
            availability = Fore.GREEN + "Available"
        table.append([book["id"], book["author"], book["title"], availability + Fore.RESET + ""])
        logger.debug(f"{book['id']} - {book['author']} - {book['title']} - {availability}")
    click.echo(tablify(table))


if __name__ == "__main__":
    cli()
