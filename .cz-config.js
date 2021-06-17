'use strict';

module.exports = {

    types : [
        { value : 'feat',       name : '特性:    一个新的特性' }, 
        { value : 'fix',        name : '修复:    修复一个Bug' },
        { value : 'docs',       name : '文档:    变更的只有文档' },
        { value : 'style',      name : '格式:    空格, 分号等格式修复' },
        { value : 'refactor',   name : '重构:    代码重构，注意和特性、修复区分开' },
        { value : 'perf',       name : '性能:    提升性能' }, 
        { value : 'test',       name : '测试:    添加一个测试' },
        { value : 'chore',      name : '工具:    开发工具变动(构建、脚手架工具等)' },
        { value : 'revert',     name : '回滚:    代码回退' }, 
        { value : 'WIP',        name : 'WIP:     Work in progress' }
    ],

    scopes : [ "应用", "算法", "系统" ],

    allowBreakingChanges: ['feat', 'fix'],
 
    // limit subject length
    subjectLimit: 100
};
