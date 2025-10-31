package com.example.demo.domain.service;


import com.example.demo.domain.dto.MemoDto;
import com.example.demo.domain.entity.Memo;
import com.example.demo.domain.repository.MemoRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.time.LocalDateTime;

import org.springframework.transaction.annotation.Transactional;

@Service
@Slf4j
public class MemoServiceImpl {

    @Autowired
    private MemoRepository memoRepository;

    @Transactional(rollbackFor=Exception.class)
    public boolean addMemo(MemoDto dto) throws Exception{
        Memo memo = new Memo();
        memo.setText(dto.getText());
        memo.setRegdate(LocalDateTime.now());
        memo.setWriter(dto.getWriter());
        memoRepository.save(memo);
        return true;
    }



}
