/**
 *
 * @param dateIsoFormat Datum ve formatu ISO
 * @param desiredFormatMask Maska vystupniho data - D=den, M=mesic, Y=rok
 * @returns {XML/string} Pozadovany format data
 */
function getDate(dateIsoFormat, desiredFormatMask) {
    var date = new Date(Date.parse(dateIsoFormat));

    var result = desiredFormatMask.replace("D", date.getDate())
        .replace("M", (date.getMonth() + 1))
        .replace("Y", date.getFullYear());

    return result;
}

function allign2digits(number) {
    if (number < 10 && number >= 0) return '0' + parseInt(number);
    return number;
}

function getIsoDateT(day, month, year, hour, minute, second) {
    day = allign2digits(day);
    month = allign2digits(month);
    hour = allign2digits(hour);
    minute = allign2digits(minute);
    second = allign2digits(second);

    return year + "-" + month + "-" + day + "T" + hour + ":" + minute + ":" + second;
}

function getIsoDate(day, month, year) {
    return getIsoDateT(day, month, year, 0, 0, 0);
}

/**
 *
 * @param humanDate Datum ve formatu D. M. Y
 */
function getIsoFromHumanDate(humanDate) {
    var dateArray = humanDate.split(".");

    var day = dateArray[0].trim();
    var month = dateArray[1].trim();
    var year = dateArray[2].trim();

    return getIsoDate(day, month, year);
}

