'use strict';

/* global BootstrapDialog, yadcf, Q, pako */

var globalFunctions = {};

(function () {
    run();

    function run() {
        globalFunctions.onHashCopyClick = onHashCopyClick;
        globalFunctions.onShowExtraClick = onShowExtraClick;
        globalFunctions.onMultiDownloadClick = onMultiDownloadClick;

        var architecture = getParameterByName('arch');
        var baseDataUrl = 'data';
        if (architecture === 'arm64' || architecture === 'insider') {
            var archTitles = {
                'arm64': 'ARM64',
                'insider': 'Insider'
            };

            $('#winbindex-arch').val(architecture).prop('disabled', false);
            $('#main-logo-link').prop('href', '?arch=' + architecture);
            $('#main-logo-arch-badge').text(archTitles[architecture]).removeClass('d-none');
            $('#arch-links a[href="."]').removeClass('active');
            $('#arch-links a[href="?arch=' + architecture + '"]').addClass('active');
            baseDataUrl = 'https://m417z.com/winbindex-data-' + architecture;
        }

        animateLogo();

        var displayFile = getParameterByName('file');
        if (displayFile) {
            if (/(^\.\.[/\\]|^\/etc\/)/.test(displayFile)) {
                location = 'https://www.youtube.com/watch?v=sTSA_sWGM44';
                return;
            }

            displayFile = displayFile.replace(/[<>:"/|?*]/g, '');
        }

        if (displayFile) {
            var newTitle = displayFile + ' - Winbindex';
            $('#main-title').text(newTitle);
            document.title = newTitle;

            var searchQuery = getParameterByName('search');

            loadFileInfoToTable(baseDataUrl, displayFile, searchQuery);
        } else {
            loadFileNames(baseDataUrl);
        }
    }

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    // Based on: https://codepen.io/riazxrazor/pen/Gjomdp
    function animateLogo() {
        var canvas = document.getElementById('main-logo-canvas');
        var ctx = canvas.getContext('2d');
        var charArr = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'];
        var fallingCharArr = [];
        var fontSize = 8;
        var ch = canvas.getBoundingClientRect().height;
        var cw = canvas.getBoundingClientRect().width;
        var maxColumns = cw / fontSize;

        canvas.width = cw;
        canvas.height = ch;

        function randomInt(min, max) {
            return Math.floor(Math.random() * (max - min + 1)) + min;
        }

        function randomFloat(min, max) {
            return Math.random() * (max - min) + min;
        }

        function Point(x, y) {
            this.x = x;
            this.y = y;
            this.speed = randomFloat(2, 5);
        }

        Point.prototype.draw = function (ctx) {
            this.value = charArr[randomInt(0, charArr.length - 1)].toUpperCase();

            ctx.fillStyle = '#0F0';
            ctx.font = fontSize + 'px san-serif';
            ctx.fillText(this.value, this.x, this.y);

            this.y += this.speed;
            if (this.y > ch) {
                this.y = randomFloat(-100, 0);
                this.speed = randomFloat(2, 5);
            }
        };

        for (var i = 0; i < maxColumns; i++) {
            fallingCharArr.push(new Point(i * fontSize, randomFloat(-500, 0)));
        }

        var animationOn = false;
        var frameDelay = 0;
        var animationFramePending = false;
        var frameCount = 0;
        var update = function () {
            ctx.fillStyle = 'rgba(0,0,0,0.05)';
            ctx.fillRect(0, 0, cw, ch);

            var i = fallingCharArr.length;

            while (i--) {
                fallingCharArr[i].draw(ctx);
            }

            frameCount++;
            if (frameCount < 100 || animationOn) {
                frameDelay = 0;
            } else {
                frameDelay += 10;
            }

            if (frameDelay < 100) {
                animationFramePending = true;
                if (frameDelay > 0) {
                    setTimeout(function () {
                        requestAnimationFrame(update);
                    }, frameDelay);
                } else {
                    requestAnimationFrame(update);
                }
            } else {
                animationFramePending = false;
            }
        };

        canvas.parentNode.onmouseover = function () {
            animationOn = true;
            if (!animationFramePending) {
                update();
            }
        };

        canvas.parentNode.onmouseout = function () {
            animationOn = false;
        };

        update();
    }

    function loadFileNames(baseDataUrl) {
        // select2 is 2 slow!
        /*$('#winbindex-file-select').select2({
            placeholder: 'Select a file',
            allowClear: true,
            data: data
        });*/

        var DataProvider = function () {
            this.availableItems = null;
            this.items = null;
        };
        DataProvider.prototype.load = function () {
            var deferred = Q.defer();
            var self = this;
            if (this.availableItems) {
                deferred.resolve();
            } else {
                $.ajax({
                    url: baseDataUrl + '/filenames.json'
                }).done(function (data) {
                    self.availableItems = [];
                    data.forEach(function (item) {
                        self.availableItems.push({
                            id: item,
                            name: item
                        });
                    });
                    self.items = self.availableItems;

                    // Prevent flickering with setTimeout.
                    setTimeout(function () {
                        $('#winbindex-file-select-container').removeClass('d-none').addClass('d-flex');
                        $('#page-loader').hide();
                    }, 0);

                    deferred.resolve();
                }).fail(function (jqXHR, textStatus) {
                    var msg = textStatus;
                    if (jqXHR.status) {
                        msg += ': status code ' + jqXHR.status;
                    }
                    alert(msg);
                });
            }
            return deferred.promise;
        };
        DataProvider.prototype.filter = function (search) {
            var searchArray = search.toLowerCase().split(/\s+/);
            if (searchArray.length > 0) {
                this.items = this.availableItems.filter(function (item) {
                    return searchArray.every(function (word) {
                        return item.name.indexOf(word) !== -1;
                    });
                });
            } else {
                this.items = this.availableItems;
            }
        };
        DataProvider.prototype.get = function (firstItem, lastItem) {
            return this.items.slice(firstItem, lastItem);
        };
        DataProvider.prototype.size = function () {
            return this.items.length;
        };
        DataProvider.prototype.identity = function (item) {
            return item.id;
        };
        DataProvider.prototype.displayText = function (item, extended) {
            if (item) {
                return item.name;
                //return extended ? item.name + ' (' + item.id + ')' : item.name;
            } else {
                return '';
            }
        };
        DataProvider.prototype.noSelectionText = function () {
            return 'Select a file';
        };
        var dataProvider = new DataProvider();

        $('#winbindex-file-select').virtualselect({
            dataProvider: dataProvider,
            onSelect: function (item) {
                $('#winbindex-file-value').val(item.id);
                $('#winbindex-file-select-container button[type=submit]').prop('disabled', false);
            },
        }).virtualselect('load');
    }

    function loadFileInfoToTable(baseDataUrl, fileToLoad, searchQuery) {
        $.extend($.fn.dataTableExt.oSort, {
            'natural-asc': function (a, b) {
                return a.localeCompare(b, undefined, { numeric: true });
            },
            'natural-desc': function (a, b) {
                return b.localeCompare(a, undefined, { numeric: true });
            }
        });

        var filesTable = $('#winbindex-table').DataTable({
            deferRender: true,
            stateSave: true,
            fnStateLoadParams: function (oSettings, oData) {
                delete oData.columns;
                oData.search.search = searchQuery || '';
            },
            oSearch: {
                sSearch: searchQuery || ''
            },
            columnDefs: [
                {
                    targets: 'target-hash',
                    width: '1%',
                    sortable: false,
                    render: function (data, type) {
                        if (!/^[a-fA-F0-9]+$/.test(data)) {
                            return '???';
                        }

                        if (type !== 'display') {
                            return data;
                        }

                        var seeMoreLink = $('<a data-toggle="tooltip" data-html="true" href="#"></a>')
                            .text(data.slice(0, 6) + '…')
                            .prop('title', escapeHtml(data) + '<br><br>Click to copy')
                            .attr('onclick', 'arguments[0].stopPropagation(); return globalFunctions.onHashCopyClick(this, "' + data + '");');

                        return seeMoreLink[0].outerHTML;
                    }
                }, {
                    targets: 'target-array-of-values',
                    render: function (data, type) {
                        if (type !== 'display') {
                            return escapeHtml(data.sort || data.title);
                        }

                        if (data.items.length === 0 || (data.items.length === 1 && data.items[0] === data.title)) {
                            return escapeHtml(data.title);
                        }

                        var itemsToShow = data.items;
                        if (itemsToShow.length > 11) {
                            itemsToShow = itemsToShow.slice(0, 5).concat(['(' + (itemsToShow.length - 10) + ' more items)']).concat(itemsToShow.slice(-5));
                        }

                        var titleSuffix = '';
                        if (data.items.length > 1) {
                            titleSuffix = ' (+' + (data.items.length - 1) + ')';
                        }

                        var element = $('<abbr data-toggle="tooltip" data-html="true"></abbr>')
                            .text(data.title + titleSuffix)
                            .prop('title', itemsToShow.map(escapeHtml).join('<br>'));

                        return element[0].outerHTML;
                    }
                }, {
                    targets: 'target-file-arch',
                    render: function (data, type) {
                        if (!data) {
                            return '???';
                        }

                        var text = humanFileArch(data);

                        return escapeHtml(text);
                    }
                }, {
                    targets: 'target-file-version',
                    type: 'natural',
                    render: function (data, type) {
                        if (!data) {
                            return '???';
                        }

                        var text = data.replace(/\s*(\(.*\)|built by:.*|@BuiltBy:.*)$/, '');

                        return escapeHtml(text);
                    }
                }, {
                    targets: 'target-file-size',
                    searchable: false,
                    render: function (data, type) {
                        if (type !== 'display') {
                            return data !== null ? data : -1;
                        }

                        if (!data) {
                            return '???';
                        }

                        return escapeHtml(humanFileSize(data));
                    }
                }, {
                    targets: 'target-file-signing-date',
                    render: function (data, type) {
                        if (!data) {
                            return '???';
                        }

                        if (data.length === 0) {
                            return '-';
                        }

                        var text = data[0].slice(0, '2000-01-01'.length);

                        return escapeHtml(text);
                    }
                }, {
                    targets: 'target-extra-button',
                    className: 'text-center',
                    width: '1%',
                    searchable: false,
                    sortable: false,
                    render: function (data) {
                        // Sort keys - https://stackoverflow.com/a/53593328
                        var allKeys = [];
                        var seen = {};
                        JSON.stringify(data.data, function (key, value) {
                            if (!(key in seen)) {
                                allKeys.push(key);
                                seen[key] = null;
                            }
                            return value;
                        });
                        allKeys.sort();
                        var json = JSON.stringify(data.data, allKeys, 4);

                        var element = $('<a href="#" class="btn btn-secondary btn-sm">Show</a>')
                            .attr('onclick', 'arguments[0].stopPropagation(); return globalFunctions.onShowExtraClick(this, "' + data.hash + '", "' + encodeURIComponent(json) + '");');

                        return element[0].outerHTML;
                    }
                }, {
                    targets: 'target-download-button',
                    className: 'text-center',
                    width: '1%',
                    searchable: false,
                    sortable: false,
                    render: function (data) {
                        var hash = data.hash;
                        var d = data.fileInfo;

                        if (d.timestamp !== undefined && d.virtualSize) {
                            var url = makeSymbolServerUrl(fileToLoad, d.timestamp, d.virtualSize);

                            var downloadLink = $('<a class="btn btn-secondary btn-sm">Download</a>')
                                .prop('href', url).attr('onclick', 'arguments[0].stopPropagation();');

                            return downloadLink[0].outerHTML;
                        }

                        if (d.timestamp !== undefined && d.size && d.lastSectionPointerToRawData && d.lastSectionVirtualAddress) {
                            var multiDownloadBtn = $('<a href="#" class="btn btn-secondary btn-sm"><abbr data-toggle="tooltip" title="Several download link candidates">Download</abbr></a>')
                                .attr('onclick', 'arguments[0].stopPropagation(); return globalFunctions.onMultiDownloadClick(this, "' + hash + '", "' + encodeURIComponent(fileToLoad) + '", ' + d.timestamp + ', ' + d.size + ', ' + d.lastSectionPointerToRawData + ', ' + d.lastSectionVirtualAddress + ');');

                            return multiDownloadBtn[0].outerHTML;
                        }

                        var msg;
                        if (/\.(exe|dll|sys|winmd|cpl|ax|node|ocx|efi|acm|scr|tsp|drv)$/.test(fileToLoad)) {
                            msg = 'Download is not available since the file isn\'t available on VirusTotal';
                        } else {
                            msg = 'Download is only available for executables such as exe, dll, and sys files';
                        }
                        return '<span class="disabled-cursor" data-toggle="tooltip" title="' + msg + '">' +
                            '<a href="#" class="btn btn-secondary btn-sm disabled">Download</a></span>';
                    }
                }, {
                    targets: 'target-plain-text',
                    render: function (data, type) {
                        if (!data) {
                            return '???';
                        }

                        return escapeHtml(data);
                    }
                }, {
                    targets: 'target-plain-text-natural',
                    type: 'natural',
                    render: function (data, type) {
                        if (!data) {
                            return '???';
                        }

                        return escapeHtml(data);
                    }
                }
            ],
            order: [[$('#winbindex-table thead th.order-default-sort').index(), 'desc']],
            preDrawCallback: function (settings) {
                this.find('[data-toggle="tooltip"]').tooltip('dispose');
            }
        });
        $('#winbindex-table').tooltip({ selector: '[data-toggle=tooltip]', boundary: 'window' });

        var yadcfColumnOptions = {
            filter_reset_button_text: false,
            filter_match_mode: 'exact',
            column_data_type: 'rendered_html',
            select_type: 'select2',
            select_type_options: {
                theme: 'bootstrap4',
                dropdownAutoWidth: true
            }
        };
        var yadcfColumns = [];
        $('#winbindex-table thead th .winbindex-column-header-with-yadcf').each(function () {
            var columnHeader = $(this);
            var columnNumber = columnHeader.parent().index();
            var filterDefaultLabel = columnHeader.text();
            var options = $.extend({
                column_number: columnNumber,
                filter_default_label: filterDefaultLabel
            }, yadcfColumnOptions);

            if (columnHeader.hasClass('winbindex-yadcf-multiple')) {
                options.text_data_delimiter = ',';
            }

            if (columnHeader.hasClass('winbindex-yadcf-natural-sort')) {
                options.sort_as = 'custom';
                options.sort_as_custom_func = function (a, b) {
                    return a.localeCompare(b, undefined, { numeric: true });
                };
            }

            yadcfColumns.push(options);
        });

        yadcf.init(filesTable, yadcfColumns);

        $.ajax({
            url: baseDataUrl + '/by_filename_compressed/' + fileToLoad + '.json.gz',
            // https://stackoverflow.com/a/17682424
            xhrFields: {
                responseType: 'blob'
            }
        }).done(function (compressed) {
            var fileReader = new FileReader();
            fileReader.onload = function (event) {
                var arrayBuffer = event.target.result;

                var data = JSON.parse(pako.ungzip(arrayBuffer, { to: 'string' }));

                var mainDescription = '';
                var mainDescriptionUpdate = '';

                var rows = [];
                Object.keys(data).forEach(function (hash) {
                    var d = data[hash];

                    var fileInfo = {};
                    var sha1 = null;
                    var md5 = null;
                    var description = null;
                    var machineType = null;
                    var signingDate = null;
                    var size = null;
                    var version = null;

                    if (d.fileInfo) {
                        fileInfo = d.fileInfo;

                        // For PE files with partial file info, if we don't have
                        // some optional data (i.e. data that not all files
                        // have), we can't know whether the real file has it.
                        // For files with full data, we know that if we don't
                        // have some optional data, it's missing in the file, so
                        // we can mark it as such.
                        //
                        // For now, we don't have a convenient indication for
                        // partial data, but we can check signingStatus, and for
                        // now that's a distinguishing factor.
                        var partialFileInfo = fileInfo.machineType && !fileInfo.signingStatus;
                        var fallbackForOptionalData = partialFileInfo ? null : '-';

                        sha1 = fileInfo.sha1 || null;
                        md5 = fileInfo.md5 || null;
                        description = fileInfo.description || null;
                        machineType = fileInfo.machineType || '-';
                        signingDate = fileInfo.signingDate || fallbackForOptionalData;
                        size = fileInfo.size || null;
                        version = fileInfo.version || fallbackForOptionalData;
                    }

                    var assemblyArchitecture = getAssemblyProcessorArchitecture(d);
                    var assemblyVersion = getAssemblyVersion(d);

                    var win10Versions = getWin10Versions(d);
                    var updateKbs = getUpdateKbs(d);

                    rows.push([
                        hash,
                        sha1,
                        md5,
                        win10Versions,
                        updateKbs,
                        machineType,
                        version,
                        size,
                        signingDate,
                        assemblyArchitecture,
                        assemblyVersion,
                        { hash: hash, data: d },
                        { hash: hash, fileInfo: fileInfo }
                    ]);

                    if (description && updateKbs.items[0] && updateKbs.items[0] > mainDescriptionUpdate) {
                        mainDescription = description;
                        mainDescriptionUpdate = updateKbs.items[0];
                    }
                });
                $('#winbindex-table-container').removeClass('winbindex-table-container-hidden');
                filesTable.rows.add(rows).draw();
                initHiddenColumns(filesTable);
                $('#page-loader').hide();

                $('#main-description').text(mainDescription);

                onFileInfoLoaded(fileToLoad);
            };
            fileReader.readAsArrayBuffer(compressed);
        }).fail(function (jqXHR, textStatus) {
            var msg = textStatus;
            if (jqXHR.status) {
                msg += ': status code ' + jqXHR.status;
            }
            alert(msg);
        });
    }

    function onFileInfoLoaded(loadedFile) {
        var match = loadedFile.match(/^(?:vcruntime|msvcp|msvcr)(140|120|110|100|90|80)(?:_.*?)?\.dll$/);
        if (match) {
            var showMsvcRedistInfo = function () {
                var redistVersion;
                var downloadLinks;

                switch (match[1]) {
                    case '140':
                        redistVersion = 'Visual Studio 2015, 2017 and 2019';
                        downloadLinks = '<ul><li>' +
                            'x86: <a href="https://aka.ms/vs/16/release/vc_redist.x86.exe">vc_redist.x86.exe</a>' +
                            '</li><li>' +
                            'x64: <a href="https://aka.ms/vs/16/release/vc_redist.x64.exe">vc_redist.x64.exe</a>' +
                            '</li></ul>';
                        break;

                    case '120':
                        redistVersion = 'Visual Studio 2013';
                        downloadLinks = '<ul><li>' +
                            'x86: <a href="https://aka.ms/highdpimfc2013x86enu">vcredist_x86.exe</a>' +
                            '</li><li>' +
                            'x64: <a href="https://aka.ms/highdpimfc2013x64enu">vcredist_x64.exe</a>' +
                            '</li></ul>';
                        break;

                    case '110':
                        redistVersion = 'Visual Studio 2012';
                        downloadLinks = '<a href="https://www.microsoft.com/en-us/download/details.aspx?id=30679" target="_blank" rel="noopener">Click here</a>, download and install both <strong>vcredist_x86.exe</strong> and <strong>vcredist_x64.exe</strong>.<br><br>';
                        break;

                    case '100':
                        redistVersion = 'Visual Studio 2010';
                        downloadLinks = '<a href="https://www.microsoft.com/en-us/download/details.aspx?id=26999" target="_blank" rel="noopener">Click here</a>, download and install both <strong>vcredist_x86.exe</strong> and <strong>vcredist_x64.exe</strong>.<br><br>';
                        break;

                    case '90':
                        redistVersion = 'Visual Studio 2008';
                        downloadLinks = '<a href="https://www.microsoft.com/en-us/download/details.aspx?id=26368" target="_blank" rel="noopener">Click here</a>, download and install both <strong>vcredist_x86.exe</strong> and <strong>vcredist_x64.exe</strong>.<br><br>';
                        break;

                    case '80':
                        redistVersion = 'Visual Studio 2005';
                        downloadLinks = '<a href="https://www.microsoft.com/en-us/download/details.aspx?id=26347" target="_blank" rel="noopener">Click here</a>, download and install both <strong>vcredist_x86.EXE</strong> and <strong>vcredist_x64.EXE</strong>.<br><br>';
                        break;
                }

                var message = 'You\'re probably here because you got an error message similar to the following:<br><br>' +
                    '<img src="assets/vc_redist_error.png" alt="The program can\'t start because VCRUNTIME140.dll is missing from your computer. Try reinstalling the program to fix this problem." class="mw-100 mx-auto d-block"><br>' +
                    'The <strong>' + escapeHtml(loadedFile) + '</strong> file is a part of the <strong>Microsoft Visual C++ Redistributable for ' + escapeHtml(redistVersion) + '</strong>. ' +
                    'The best way to fix the error is to install the Visual C++ redistributable package.<br><br>' +
                    'Download and install both the x86 and x64 versions of the Visual C++ redistributable package:<br>' +
                    downloadLinks +
                    'As a last resort, you can try downloading the missing files from Winbindex, but note that since the files are not an integral part of Windows, they are usually not uploaded to the symbol server, and even when they do, they might not be up-to-date with the latest version.';

                BootstrapDialog.show({
                    title: 'Download Microsoft Visual C++ Redistributable',
                    message: message,
                    buttons: [{
                        label: 'Close',
                        action: function (dialog) {
                            dialog.close();
                        }
                    }]
                });
            };

            var infoButtonHtml = '<button type="button" class="btn btn-primary">Download Microsoft Visual C++ Redistributable</button>';
            var infoButton = $(infoButtonHtml).click(showMsvcRedistInfo);
            $('#main-description').after($('<div class="text-center mt-2"></div>').append(infoButton));

            showMsvcRedistInfo();
        }
    }

    function initHiddenColumns(table) {
        var hiddenColumns = localStorage.getItem('winbindex-hidden-columns');
        if (!hiddenColumns) {
            hiddenColumns = [];
            $('#winbindex-table thead th.hidden-by-default').each(function () {
                hiddenColumns.push($(this).index());
            });
        }

        table.columns(hiddenColumns).visible(false);

        var settingsButton = $('#winbindex-settings-button');
        $('#winbindex-table_filter').append(settingsButton);

        settingsButton.find('.dropdown-menu .dropdown-item-column').each(function (columnIndex) {
            if (hiddenColumns.indexOf(columnIndex) === -1) {
                $(this).find('input[type="checkbox"]').prop('checked', true);
            }

            $(this).click(function () {
                toggleHiddenColumn(this, table, columnIndex);
                return false;
            });
        });

        settingsButton.find('.dropdown-menu .dropdown-item-full-width').click(function () {
            var checkbox = $(this).find('input[type="checkbox"]');
            var checked = checkbox.prop('checked');
            if (checked) {
                $('body div.container-fluid').removeClass('container-fluid').addClass('container');
            } else {
                $('body div.container').removeClass('container').addClass('container-fluid');
            }
            checkbox.prop('checked', !checked);
            return false;
        });
    }

    function toggleHiddenColumn(element, table, columnIndex) {
        var checkbox = $(element).find('input[type="checkbox"]');
        var checked = checkbox.prop('checked');
        table.column(columnIndex).visible(!checked);
        checkbox.prop('checked', !checked);
    }

    function getAssemblyParam(data, param) {
        var items = {};

        var windowsVersions = data.windowsVersions;
        Object.keys(windowsVersions).forEach(function (windowsVersion) {
            Object.keys(windowsVersions[windowsVersion]).forEach(function (update) {
                if (update !== 'BASE') {
                    var assemblies = windowsVersions[windowsVersion][update].assemblies;
                    Object.keys(assemblies).forEach(function (assembly) {
                        var paramValue = assemblies[assembly].assemblyIdentity[param];
                        if (paramValue) {
                            items[paramValue] = true;
                        }
                    });
                }
            });
        });

        return Object.keys(items);
    }

    function getAssemblyProcessorArchitecture(data) {
        var items = getAssemblyParam(data, 'processorArchitecture');

        items = items.map(function (item) {
            return humanFileArch(item);
        });

        items.sort();

        var title = items[0] || '-';

        return {
            items: items,
            title: title,
            sort: items.join(',') || title
        };
    }

    function getAssemblyVersion(data) {
        var items = getAssemblyParam(data, 'version');

        items.sort(function (a, b) {
            return a.localeCompare(b, undefined, { numeric: true });
        });

        var title = items[0] || '-';

        return {
            items: items,
            title: title,
            sort: items.join(',') || title
        };
    }

    function getWin10Versions(data) {
        var windowsVersions = data.windowsVersions;

        var items = Object.keys(windowsVersions);
        if (items.length === 1 && items[0] === 'builds') {
            items = [];

            Object.keys(windowsVersions['builds']).forEach(function (update) {
                var updateInfo = windowsVersions['builds'][update].updateInfo;
                var title = updateInfo.title
                    .replace(/^(\d{4}-\d{2} )?Cumulative Update Preview for /, '')
                    .replace(/^(\d{4}-\d{2} )?Cumulative Update for /, '')
                    .replace(/^(\d{4}-\d{2} )?Feature update to /, '')
                    .replace(/^(\d{4}-\d{2} )?Update for /, '');
                var windowsVersion = title;
                var match;
                if ((match = /^Microsoft server operating system,? version (\w+)/.exec(title))) {
                    windowsVersion = 'Windows Server ' + match[1];
                } else if ((match = /^Windows (\d+|Server) Insider Preview/.exec(title))) {
                    windowsVersion = 'Windows ' + match[1] + ' Insider';
                } else if ((match = /^Windows (\d+|Server),? [vV]ersion (\w+)/.exec(title))) {
                    windowsVersion = 'Windows ' + match[1] + ' ' + match[2];
                } else if ((match = /^Windows Server (\w+) [(-]/.exec(title))) {
                    windowsVersion = 'Windows Server ' + match[1];
                } else if ((match = /^Windows (\d+) (?:[(-]|for \w+-based)/.exec(title))) {
                    windowsVersion = 'Windows ' + match[1];
                } else if ((match = /^Azure Stack HCI, version (\w+)/.exec(title))) {
                    windowsVersion = 'Azure Stack HCI ' + match[1];
                }

                // Remove commas as they're used as separators in filtering.
                windowsVersion = windowsVersion.replace(/\s*,\s*/g, ' ');

                if (items.indexOf(windowsVersion) === -1) {
                    items.push(windowsVersion);
                }
            });
        } else {
            Object.keys(windowsVersions).forEach(function (windowsVersion) {
                Object.keys(windowsVersions[windowsVersion]).forEach(function (update) {
                    if (update === 'BASE') {
                        return;
                    }

                    var updateInfo = windowsVersions[windowsVersion][update].updateInfo;
                    if (!updateInfo.otherWindowsVersions) {
                        return;
                    }

                    updateInfo.otherWindowsVersions.forEach(function (otherWindowsVersion) {
                        if (items.indexOf(otherWindowsVersion) === -1) {
                            items.push(otherWindowsVersion);
                        }
                    });
                });
            });

            items = items.map(function (item) {
                var split = item.split('-', 2);
                if (split.length === 1) {
                    return 'Windows 10 ' + split[0];
                }

                return 'Windows ' + split[0] + ' ' + split[1];
            });
        }

        items.sort();

        var title = items[0] || '-';

        return {
            items: items,
            title: title,
            sort: items.join(',') || title
        };
    }

    function getUpdateKbs(data) {
        var items = [];

        var windowsVersions = data.windowsVersions;
        Object.keys(windowsVersions).forEach(function (windowsVersion) {
            Object.keys(windowsVersions[windowsVersion]).forEach(function (update) {
                var itemText;
                if (update === 'BASE') {
                    var windowsVersionInfo = windowsVersions[windowsVersion][update].windowsVersionInfo;
                    var baseDate = windowsVersionInfo.releaseDate;
                    itemText = baseDate + ' - Base ' + windowsVersion;
                } else if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(update)) {
                    var updateUupInfo = windowsVersions[windowsVersion][update].updateInfo;
                    var updateUupDate = new Date(updateUupInfo.created * 1000).toISOString().slice(0, '2000-01-01'.length);
                    itemText = updateUupDate + ' - ' + update.slice(0, 8);
                } else {
                    var updateInfo = windowsVersions[windowsVersion][update].updateInfo;
                    var updateDate = updateInfo.releaseDate.slice(0, '2000-01-01'.length);
                    itemText = updateDate + ' - ' + update;
                }
                items.push(itemText);
            });
        });

        items.sort();

        var title = '-';
        if (items.length > 0) {
            title = items[0].slice('2000-01-01 - '.length);
        }

        return {
            items: items,
            title: title,
            sort: items.join(',') || title
        };
    }

    // https://stackoverflow.com/a/20732091
    function humanFileSize(size) {
        var i = size === 0 ? 0 : Math.floor(Math.log(size) / Math.log(1024));
        return (size / Math.pow(1024, i)).toFixed(2) * 1 + ' ' + ['B', 'KB', 'MB', 'GB', 'TB'][i];
    }

    function humanFileArch(arch) {
        switch (arch) {
            case 332:
                return 'x86';

            case 34404:
                return 'x64';

            case 452:
                return 'ARM';

            case 43620:
                return 'ARM64';
        }

        return arch.toString();
    }

    function makeSymbolServerUrl(peName, timeStamp, imageSize) {
        // "%s/%s/%08X%x/%s" % (serverName, peName, timeStamp, imageSize, peName)
        // https://randomascii.wordpress.com/2013/03/09/symbols-the-microsoft-way/

        var fileId = ('0000000' + timeStamp.toString(16).toUpperCase()).slice(-8) + imageSize.toString(16).toLowerCase();
        return 'https://msdl.microsoft.com/download/symbols/' + peName + '/' + fileId + '/' + peName;
    }

    function onHashCopyClick(element, hash) {
        var elem = $(element);

        if (elem.attr('data-copying')) {
            return false;
        }

        elem.attr('data-copying', 'true');

        function onCopied(msg) {
            var previousText = elem.attr('data-original-title');
            elem.attr('data-original-title', msg).tooltip('show');
            setTimeout(function () {
                elem.attr('data-original-title', previousText).removeAttr('data-copying');
            }, 500);
        }

        copyToClipboard(hash,
            function () {
                onCopied('Copied');
            }, function () {
                onCopied('Error');
            }
        );

        return false;
    }

    function onShowExtraClick(element, fileHash, encoded) {
        var text = decodeURIComponent(encoded);

        BootstrapDialog.show({
            title: 'Extra info',
            message: $('<pre class="winbindex-scrollable-info-box-contents"></pre>').text(text),
            size: BootstrapDialog.SIZE_WIDE,
            onshow: function (dialog) {
                var modalBody = dialog.getModalBody();
                modalBody.css('padding', '0');
            },
            buttons: [{
                label: 'Download',
                action: function (dialog) {
                    downloadFile(fileHash + '.json', text);
                }
            }, {
                label: 'Copy to clipboard',
                action: function (dialog) {
                    var button = $(this);
                    copyToClipboard(text, function () {
                        button.prop('title', 'Copied').tooltip('show');
                        setTimeout(function () {
                            button.removeProp('title').tooltip('dispose');
                        }, 500);
                    }, function () {
                        alert('Failed to copy to clipboard');
                    });
                }
            }, {
                label: 'Close',
                action: function (dialog) {
                    dialog.close();
                }
            }]
        });

        return false;
    }

    function onMultiDownloadClick(element, fileHash, peName, timeStamp, fileSize, lastSectionPointerToRawData, lastSectionVirtualAddress) {
        // Algorithm inspired by DeltaDownloader:
        // https://github.com/Wack0/DeltaDownloader/blob/ab71359fc5a1f2446b650b31450c74a701c40979/Program.cs#L68-L85

        var PAGE_SIZE = 0x1000;

        function getMappedSize(size) {
            var PAGE_MASK = (PAGE_SIZE - 1);
            var page = size & ~PAGE_MASK;
            if (page == size) return page;
            return page + PAGE_SIZE;
        }

        // We use the rift table (VirtualAddress,PointerToRawData pairs for each section) and the target file size to calculate the SizeOfImage.
        var lastSectionAndSignatureSize = fileSize - lastSectionPointerToRawData;
        var lastSectionAndSignatureMappedSize = getMappedSize(lastSectionVirtualAddress + lastSectionAndSignatureSize);

        var sizeOfImage = lastSectionAndSignatureMappedSize;
        var lowestSizeOfImage = lastSectionVirtualAddress + PAGE_SIZE;

        var urlsStr = '';
        var urls = $('<div>');
        for (var size = sizeOfImage; size >= lowestSizeOfImage; size -= PAGE_SIZE) {
            var url = makeSymbolServerUrl(peName, timeStamp, size);
            urlsStr += url + '\n';
            urls.append($('<a>', {
                href: url
            }).text(url)).append('<br>');
        }

        var messageHtml = 'This file is indexed with a limited amount of information. ' +
            'It\'s not possible to generate the exact download link, but it\'s possible ' +
            'to generate several download link candidates, one of which is likely to be ' +
            'the correct link. You can just try these links one by one (usually one of the ' +
            'first links is the correct one), or you can feed this list to a download tool ' +
            'such as curl, wget or aria2. For more details, refer to ' +
            '<a href="https://m417z.com/Winbindex-Download-Links-From-80-to-100-ish/" target="_blank">the relevant blog post</a>.';
        var message = $('<div class="winbindex-scrollable-info-box-contents">' + messageHtml + '</div>')
            .append('<br><br>').append(urls);

        BootstrapDialog.show({
            title: 'Several download link candidates',
            message: message,
            size: BootstrapDialog.SIZE_WIDE,
            onshow: function (dialog) {
                var modalBody = dialog.getModalBody();
                modalBody.css('padding', '0');
            },
            buttons: [{
                label: 'Download list',
                action: function (dialog) {
                    downloadFile(fileHash + '_urls.txt', urlsStr);
                }
            }, {
                label: 'Copy to clipboard',
                action: function (dialog) {
                    var button = $(this);
                    copyToClipboard(urlsStr, function () {
                        button.prop('title', 'Copied').tooltip('show');
                        setTimeout(function () {
                            button.removeProp('title').tooltip('dispose');
                        }, 500);
                    }, function () {
                        alert('Failed to copy to clipboard');
                    });
                }
            }, {
                label: 'Close',
                action: function (dialog) {
                    dialog.close();
                }
            }]
        });

        return false;
    }

    // https://stackoverflow.com/a/18197341
    function downloadFile(filename, text) {
        var element = document.createElement('a');
        element.setAttribute('href', 'data:text/plain;charset=utf-8,' + encodeURIComponent(text));
        element.setAttribute('download', filename);

        element.style.display = 'none';
        document.body.appendChild(element);

        element.click();

        document.body.removeChild(element);
    }

    // https://stackoverflow.com/a/901144
    function getParameterByName(name, url) {
        if (!url) url = window.location.href;
        name = name.replace(/[[\]]/g, '\\$&');
        var regex = new RegExp('[?&]' + name + '(=([^&#]*)|&|#|$)'),
            results = regex.exec(url);
        if (!results) return null;
        if (!results[2]) return '';
        return decodeURIComponent(results[2].replace(/\+/g, ' '));
    }

    // https://stackoverflow.com/a/30810322
    function copyToClipboard(text, onSuccess, onFailure) {
        if (!navigator.clipboard) {
            fallbackCopyTextToClipboard(text);
            return;
        }
        // eslint-disable-next-line compat/compat
        navigator.clipboard.writeText(text).then(function () {
            onSuccess();
        }, function (err) {
            onFailure();
        });

        function fallbackCopyTextToClipboard(text) {
            var textArea = document.createElement('textarea');
            textArea.value = text;
            document.body.appendChild(textArea);
            textArea.focus();
            textArea.select();

            var successful = false;
            try {
                successful = document.execCommand('copy');
            } catch (err) {
                // We tried...
            }

            document.body.removeChild(textArea);

            if (successful) {
                onSuccess();
            } else {
                onFailure();
            }
        }
    }

    // https://stackoverflow.com/a/6234804
    function escapeHtml(unsafe) {
        return unsafe
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }
})();
